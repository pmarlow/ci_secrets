# ci_secrets

`ci_secrets` is a tool for detecting leaked secrets in Git repositories in a DevOps friendly way. It provides an enforceable way to detect when a secret has been leaked by running within the CI/CD pipeline. When it detects a leak, it fails the build. If a merge/pull request is created including a leak, it will also fail that build. It minimizes re-work by only searching back as far as the previously published commit. In the case of a merge, it will search back to the most recent common ancestor to ensure no commits avoid scanning.

N.B. To be effective, `ci_secrets` must be run on **ALL** commits. Otherwise, unscanned commits may still contain leaked secrets.

For an in-depth look at how it works and it's strengths and limitations, check out the whitepaper here: [Finding Secrets in Source Code the DevOps Way [PDF]](https://www.sans.org/reading-room/whitepapers/securecode/finding-secrets-source-code-devops-38985) (Marlow, 2019).

## Configuring Detection Plugins

The detection plugins define how `ci_secrets` identifies leaked secrets. Plugins must be compliant with the `detect-secrets` plugin definition. Pre-existing plugins can be found here: https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins

To configure which plugins to use, create a `.ci_secrets.yml` file in the root of your project. For an example, see `example.ci_secrets.yml`. If any plugins require a configuration parameter, it can be supplied as the value for the detector key.

## Running in GitLab CI

See `example.gitlab-ci.yml` for an example of how to configure `ci_secrets` within a GitLab CI pipeline.

GitLab CI provides separate environment variables for the last commit (`CI_COMMIT_BEFORE_SHA`) and for the target of a merge request (`CI_MERGE_REQUEST_TARGET_BRANCH_NAME`). This means that scans need to be specified separately depending on whether it is a merge request or not. This is done using the `only` and `except` keywords.

## Running in Travis CI

See `example.travis.yml` for an example of how to configure `ci_secrets` within a Travis CI pipeline.

Travis CI provides the `TRAVIS_COMMIT_RANGE` environment variable which specifies the commits that are included within the push or pull request. `ci_secrets` determines the latest-scanned commit from the first commit in the range provided as `TRAVIS_COMMIT_RANGE` environment variable’s value. If it is the first commit on a new branch, this variable is empty. Because ci_secrets requires a value for the last scanned commit, a user can pass the flag value of `0000000000000000000000000000000000000000` when `TRAVIS_COMMIT_RANGE` is empty.

When creating a pull request using GitHub and scanning with Travis CI, a merge commit is first created and then passed to the CI system. The completed merge commit presents a challenge because `ci_secrets` cannot determine if this merge commit is a result of a pull request, or if the previous commit just happened to be a merge commit. Therefore, the caller needs to specify whether or not the pull request contains a merge commit. `ci_secrets` provides the `--includesMergeCommit` flag for this purpose, and it should be specified when scanning pull requests from GitHub in Travis CI.
