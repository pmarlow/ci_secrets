import argparse
import logging
from git import Repo
import detect_secrets.plugins.aws
import detect_secrets.plugins.private_key

logging.basicConfig(format='%(asctime)s %(message)s',level=logging.WARNING)
logger = logging.getLogger(__name__)

def main():
	logger.debug("Hello")
	parser = argparse.ArgumentParser()
	parser.add_argument("--path", dest="path")
	parser.add_argument("--since", dest="sinceCommit")
	parser.add_argument("--log", dest="log_level")
	args = parser.parse_args()
	set_log_level(args.log_level)
	repo = Repo(args.path)
	commit = repo.head.commit
	common_ancestors = set(repo.merge_base(commit, args.sinceCommit, "--all"))
	logger.info("Found common ancestors: "+', '.join([common_ancestor.hexsha for common_ancestor in common_ancestors]))
	finding_count = 0
	while set(commit.parents).isdisjoint(common_ancestors):
		finding_count += check_commit_for_secrets(commit)
		commit = commit.parents[0]
	print("Found {count} total findings.".format(count=finding_count))
	if finding_count > 0:
		return 1
	return 0

def check_commit_for_secrets(commit):
	logger.info(("*"*20)+commit.hexsha+("*"*20))
	finding_count = 0
	for diffs in commit.diff(commit.parents[0], create_patch=True):
		finding_count += check_diff_for_secrets(diffs.diff, commit.hexsha)
	return finding_count

def check_diff_for_secrets(diff, commit_sha):
	diff_string = diff.decode('utf-8')
	logger.debug("DIFF: "+diff_string)
	plugins = [detect_secrets.plugins.aws.AWSKeyDetector(),detect_secrets.plugins.private_key.PrivateKeyDetector()]
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