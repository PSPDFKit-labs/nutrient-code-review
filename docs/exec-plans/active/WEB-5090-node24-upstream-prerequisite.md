# WEB-5090: Node 24 upstream prerequisite

## Scope

Update this composite action and its own CI to immutable Node 24 action releases. This is the upstream prerequisite for the monorepo migration; it does not change the application Node.js version, reviewer implementation, public action contract, or hosted repositories.

## Constraints

- Preserve trigger, draft, cache/reservation, explicit PR-head checkout, check-run, permission, and failure behavior.
- Pin actions by full commit SHA and retain major-version comments.
- Validate runtime declarations from a recorded offline action-metadata fixture and separately inspect the live GitHub metadata for every adopted SHA.
- Hosted workflow validation requires a separately approved disposable repository and remains out of scope.

## Implementation

1. Add a focused YAML-based dependency-runtime checker plus recorded metadata fixtures and tests, including nested local composites and action subpaths.
2. Demonstrate it rejects the pre-migration Node 20 action graph, then update root composite and relevant repository CI action pins to Node 24 releases.
3. Keep `setup-node` package-manager caching explicitly disabled, because this action has no package-manager cache contract.
4. Document the GitHub runner prerequisite separately from the Node.js version installed for the reviewer.

## Verification

Run the checker, its focused tests, existing script/Python/Bun tests, YAML/actionlint validation when available, shellcheck for changed shell code if any, and `git diff --check`. Record live GitHub API runtime metadata and release/tag evidence without invoking workflows.

## Limitations

No sandbox repository is authorized. Cold/hit cache, artifact upload/download, token, review/comment/check-run, and failure/draft/command hosted behavior remain pending hosted validation.
