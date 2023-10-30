# How to contribute to LLDAP

## Did you find a bug?

 - Make sure there isn't already an [issue](https://github.com/lldap/lldap/issues?q=is%3Aissue+is%3Aopen) for it.
 - Check if the bug still happens with the `latest` docker image, or the `main` branch if you compile it yourself.
 - [Create an issue](https://github.com/lldap/lldap/issues/new) on GitHub. What makes a great issue:
   - A quick summary of the bug.
   - Steps to reproduce.
   - LLDAP _verbose_ logs when reproducing the bug. Verbose mode can be set through environment variables (`LLDAP_VERBOSE=true`) or in the config (`verbose = true`).
   - What you expected to happen.
   - What actually happened.
   - Other notes (what you tried, why you think it's happening, ...).

## Are you requesting integration with a new service?

 - Check if there is already an [example config](https://github.com/lldap/lldap/tree/main/example_configs) for it.
 - Try to figure out the configuration values for the new service yourself.
   - You can use other example configs for inspiration.
   - If you're having trouble, you can ask on [Discord](https://discord.gg/h5PEdRMNyP)
   - If you succeed, make sure to contribute an example configuration, or a configuration guide.
 - If you hit a block because of an unimplemented feature, go to the next section.

## Are you asking for a new feature?

 - Make sure there isn't already an [issue](https://github.com/lldap/lldap/issues?q=is%3Aissue+is%3Aopen) for it.
 - [Create an issue](https://github.com/lldap/lldap/issues/new) on GitHub. What makes a great feature request:
   - A quick summary of the feature.
   - Motivation: what problem does the feature solve?
   - Workarounds: what are the currently possible solutions to the problem, however bad?

## Do you want to work on a PR?

That's great! There are 2 main ways to contribute to the project: documentation and code.

### Documentation

The simplest way to contribute is to submit a configuration guide for a new
service: it can be an example configuration file, or a markdown guide
explaining the steps necessary to configure the service.

We also have some 
[documentation](https://github.com/lldap/lldap/tree/main/docs) with more
advanced guides (scripting, migrations, ...) you can contribute to.

### Code

If you don't know what to start with, check out the 
[good first issues](https://github.com/lldap/lldap/labels/good%20first%20issue). 

Otherwise, if you want to fix a specific bug or implement a feature, make sure
to start by creating an issue for it (if it doesn't already exist). There, we
can discuss whether it would be likely to be accepted and consider design
issues. That will save you from going down a wrong path, creating an entire PR
before getting told that it doesn't align with the project or the design is 
flawed!

Once we agree on what to do in the issue, you can start working on the PR. A good quality PR has:
 - A description of the change.
   - The format we use for both commit titles and PRs is:
     `tag: Do the thing`
     The tag can be: server, app, docker, example_configs, ... It's a broad category.
     The rest of the title should be an imperative sentence (see for instance [Commit Message
     Guidelines](https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53)).
   - The PR should refer to the issue it's addressing (e.g. "Fix #123").
   - Explain the _why_ of the change.
   - But also the _how_.
   - Highlight any potential flaw or limitation.
 - The code change should be as small as possible while solving the problem.
   - Don't try to code-golf to change fewer characters, but keep logically separate changes in
     different PRs.
 - Add tests if possible.
   - The tests should highlight the original issue in case of a bug.
   - Ideally, we can apply the tests without the rest of the change and they would fail. With the
     change, they pass.
   - In some areas, there is no test infrastructure in place (e.g. for frontend changes). In that
     case, do some manual testing and include the results (logs for backend changes, screenshot of a
     successful service integration, screenshot of the frontend change).
   - For backend changes, the tests should cover a significant portion of the new code paths, or
     everything if possible. You can also add more tests to cover existing code.
 - Of course, make sure all the existing tests pass. This will be checked anyway in the GitHub CI.

### Workflow

We use [GitHub Flow](https://docs.github.com/en/get-started/quickstart/github-flow):
 - Fork the repository.
 - (Optional) Create a new branch, or just use `main` in your fork.
 - Make your change.
 - Create a PR.
 - Address the comments by adding more commits to your branch (or to `main`).
 - The PR gets merged (the commits get squashed to a single one).
 - (Optional) You can delete your branch/fork.

## Reminder

We're all volunteers, so be kind to each other! And since we're doing that in our free time, some
things can take a longer than expected.
