# CLAUDE.md

## Communication

**Discuss in ASD-STE100 (Simplified Technical English).** This applies to
conversation in the terminal: answers, questions, explanations, and design
discussion.

Follow the STE writing rules:

- Write short sentences. Use 20 words or less for an instruction, 25 words or
  less for a description.
- Write 6 sentences or less in a paragraph.
- Use the active voice. Use the simple present tense when you can.
- Give one idea in one sentence.
- Use one word for one meaning. Do not change the word for the same thing.
- Use a vertical list when there are more than two related items.
- Do not use `-ing` forms, unless the word is a technical name.
- Do not use more than three nouns together.
- Use approved, common words. Write "use", not "utilize". Write "get", not
  "obtain". Write "before", not "prior to".

Repository prose keeps its existing voice. `README.md`, `CONTEXT.md`, and the
ADRs in `docs/adr/` are written in full English, and new documents must agree
with them. The STE rule is for discussion, not for the repository.

## Project

`CONTEXT.md` holds the domain language and the design. Read it before you change
behaviour. `docs/adr/` holds the decisions and the reasons for them.

## Development

The project is test-first. A pre-commit hook formats the tree and stops the
commit on any failure.

```bash
deno task check    # fmt + lint + type-check + test — the same gates as the hook
deno task test     # the suite only
```

The SSHSIG and age tests drive the real `ssh-keygen` and `age` binaries. Both
must be on `PATH` to run the suite.
