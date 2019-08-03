import argparse
import logging
from git import Repo
import detect_secrets.plugins
import yaml
import pkgutil

logging.basicConfig(format='%(asctime)s %(message)s',level=logging.WARNING)
logger = logging.getLogger(__name__)

def main():
	logger.debug("Hello")	
	with open(".ci_secrets.yml", 'r') as ymlfile:
		cfg = yaml.load(ymlfile)
	if 'log_level' in cfg.keys():
		set_log_level(cfg['log_level'])
	plugin_types = _get_plugins(cfg['plugins'].keys())
	plugins = []
	for plugin in plugin_types:
		logger.debug("Configuring: {name}({param})".format(name=plugin.__name__,param=str(cfg['plugins'][plugin.__name__])))
		if cfg['plugins'][plugin.__name__] != True:
			plugins.append(plugin(cfg['plugins'][plugin.__name__]))
		else:
			plugins.append(plugin())
	
	parser = argparse.ArgumentParser()
	parser.add_argument("--path", dest="path")
	parser.add_argument("--since", dest="since_commit")
	parser.add_argument("--log", dest="log_level")
	parser.add_argument("--includeDelete", action="store_true", dest="include_delete")
	parser.add_argument("--includesMergeCommit", action="store_true", dest="includes_merge_commit")
	args = parser.parse_args()
	set_log_level(args.log_level)
	if args.since_commit is None:
		logger.error("--since is a required argument.")
		return 1
	if args.since_commit == "0000000000000000000000000000000000000000":
		logger.warn("0000000000000000000000000000000000000000 is an invalid commit. Is this a new branch?")
		logger.warn("Assuming the new branch is only 1 commit ahead. This scan may miss credentials.")
		# Assume this is a new branch and make a best guess that it's only a single commit ahead.
		args.since_commit = "HEAD^"
	repo = Repo(args.path)
	commit = repo.head.commit
	common_ancestors = set(repo.merge_base(commit, args.since_commit, "--all"))
	logger.info("Found common ancestors: "+', '.join([common_ancestor.hexsha for common_ancestor in common_ancestors]))
	if len(common_ancestors) == 0:
		logger.warn("There are no common ancestors between these commits: "+commit.hexsha+", "+str(args.since_commit))
		return 0
	if commit in common_ancestors:
		logger.warn(args.since_commit+" is not an ancestor of itself.")
		return 0
	finding_count = 0
	continue_scanning = True
	while continue_scanning:
		finding_count += check_commit_for_secrets(commit, args.include_delete, plugins)
		continue_scanning = set(commit.parents).isdisjoint(common_ancestors)
		if commit == repo.head.commit and args.includes_merge_commit and len(repo.head.commit.parents) > 1:
			logger.info("Scanning pull request for branch including: {commit_sha}".format(commit_sha=commit.parents[1].hexsha))
			# This is a merge commit for a pull request and we want to scan the new branch, not the old one.
			commit = commit.parents[1]
			# Don't stop scanning at the merge commit, wait last for the common ancestor before this merge.
			continue_scanning = True
		else:
			commit = commit.parents[0]
	print("Found {count} total findings.".format(count=finding_count))
	if finding_count > 0:
		return 1
	return 0

def check_commit_for_secrets(commit, include_delete, plugins):
	logger.info(("*"*20)+commit.hexsha+("*"*20))
	finding_count = 0
	if include_delete:
		diffs = commit.parents[0].diff(commit, None, True)
	else:
		diffs = commit.parents[0].diff(commit, None, True, diff_filter="d")
	for diff in diffs:
		finding_count += check_diff_for_secrets(diff.diff, commit.hexsha, plugins)
	return finding_count

def check_diff_for_secrets(diff, commit_sha, plugins):
	diff_string = diff.decode('utf-8')
	logger.debug("DIFF: "+diff_string)
	return _scan_string(diff_string, plugins, commit_sha)

def _scan_string(line, plugins, commit_sha):
	logger.debug("LINE: "+line)
	finding_count = 0
	for plugin in plugins:
		results = plugin.analyze_string(line,0,'does not matter')
		for result in results:
			print("{type} ({hash}) at commit {commit}".format(type=result.type,hash=result.secret_hash,commit=commit_sha))
			finding_count += 1
	return finding_count

def set_log_level(log_level):
	if log_level is not None:
		numeric_log_level = getattr(logging, log_level.upper(), None)
		if not isinstance(numeric_log_level, int):
			raise ValueError('Invalid log level: %s' % log_level)
		logger.setLevel(numeric_log_level)

def _load_plugins():
	for importer, modname, ispkg in pkgutil.walk_packages(detect_secrets.plugins.__path__,'detect_secrets.plugins.'):
		__import__(modname)

def _all_plugins(base):
    return set(base.__subclasses__()).union(
        [s for c in base.__subclasses__() for s in _all_plugins(c)])

def _get_plugins(names):
	_load_plugins()
	available_plugins = _all_plugins(detect_secrets.plugins.base.BasePlugin)
	plugins = []
	for plugin in available_plugins:
		if plugin.__name__ in names:
			plugins.append(plugin)
	return plugins
