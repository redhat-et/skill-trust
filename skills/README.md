# Signed skills

This directory holds the repository's own agent skills, sealed with
skill-trust signatures and verified on every pull request by the
[`verify-skills` workflow](../.github/workflows/verify-pr.yml) through the
reusable [`verify-skills` action](../.github/actions/verify-skills/action.yml).

Changing any file in a skill directory requires re-signing it so the
signature covers the new content:

```console
$ skill-trust sign skills/demo-skill --key .github/skill-trust/demo-signing.key
$ git add skills/demo-skill
```

See [`.github/skill-trust/README.md`](../.github/skill-trust/README.md) for
the signing material and its trust semantics.
