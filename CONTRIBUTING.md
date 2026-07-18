# Contributing

## Commit messages

Release automation uses Conventional Commits to determine the next semantic
version and to generate the changelog. Use one of these prefixes for pull
request titles and squash commits:

```text
fix: correct timeout handling
feat: add JSON output
feat!: change the configuration format
docs: update installation instructions
chore: refresh dependencies
```

`fix` creates a patch release, `feat` creates a minor release, and `!` (or a
`BREAKING CHANGE:` footer) creates a major release. Documentation and routine
maintenance changes do not create a release.

While cleanscan is below `1.0.0`, feature releases advance the minor version.

## Releases

After a releasable change reaches `main`, Release Please opens a version PR
that updates `Cargo.toml`, the lockfile when necessary, and `CHANGELOG.md`.
Review and merge the release PR after required CI checks pass. GitHub Actions
then builds the four supported targets, uploads archives and SHA256 checksums
to a draft release, and publishes it only after every build passes. No custom
GitHub secret is required.
