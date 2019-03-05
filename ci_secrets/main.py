import argparse
from git import Repo
import detect_secrets.plugins.aws
import detect_secrets.plugins.private_key

def main():
	print("Hello")
	parser = argparse.ArgumentParser()
	parser.add_argument("--path", dest="path")
	parser.add_argument("--since", dest="sinceCommit")
	args = parser.parse_args()
	repo = Repo(args.path)
	commit = repo.head.ref.commit
	while commit.hexsha != args.sinceCommit:
		check_commit_for_secrets(commit)
		commit = commit.parents[0]

def check_commit_for_secrets(commit):
	print("*"*50,commit.hexsha)
	for diffs in commit.diff(commit.parents[0], create_patch=True):
		check_diff_for_secrets(diffs.diff)

def check_diff_for_secrets(diff):
	#print(diff)
	plugins = [detect_secrets.plugins.aws.AWSKeyDetector(),detect_secrets.plugins.private_key.PrivateKeyDetector()]
	_scan_string(diff.decode('utf-8'), plugins)

def _scan_string(line, plugins):
	#print("LINE: ",line)
	for plugin in plugins:
		results = plugin.analyze_string(line,0,'does not matter')
		for result in results:
			print(result.type, result.secret_hash)
