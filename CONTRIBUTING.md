# Contributing

This repository is a single investigation write-up, so contributions are almost always **corrections**. They are welcome — but the whole value of the document is that every claim can be traced to an event field, so the bar for changing one is the same.

## Ground rule

**A change to an answer must cite the event field that supports it.**

| Not actionable | Actionable |
| --- | --- |
| "Q6 is 1, not 0." | "`EventID=4624` with `TargetUserName=Alberto` at `UtcTime 2022-02-14 12:44:07`, `Hostname=WORKSTATION6`." |
| "The URL is wrong." | "Decoding the `Host Application` blob yields `http://10.10.10.5/admin/get.php` in this copy of the dataset; `Sequence Number` 728." |
| "Add more explanation." | Open a discussion instead — no citation needed for prose that does not change a finding. |

If you cannot quote the field, the finding stays as it is. That is not gatekeeping: an unsupported "correction" in a security write-up becomes the answer the next reader submits, and nobody can tell where it came from.

## What else is fair game

- **SPL improvements.** A query that is faster, narrower, or returns the same evidence more directly. Paste the query and the result count it produces.
- **Typos, broken anchors, unclear wording.** No evidence required.
- **Missed artifacts.** If the dataset holds something the walkthrough should have picked up — a second `4688`, an unusual `Channel` — that is a genuinely valuable find. Say what you searched for and what came back.

## Working on the file

1. Branch off `main`.
2. Edit `README.md`. Keep each question's structure intact: **Objective → Approach → SPL → Evidence → Answer**.
3. Keep evidence as tables of field values, not screenshots. A screenshot cannot be re-run.
4. Run the checks:

   ```bash
   python3 scripts/check-docs.py
   ```

   This validates that local links resolve, that the table of contents matches the headings, and that no `images/` references were reintroduced.
5. Open a pull request against `main` and fill in the template.

## Deliberate omissions

These are choices, not oversights, so please do not "fix" them:

- **No screenshots.** The write-up documents field values and queries instead.
- **Caveats stay in.** The **limitation** notes on Q4, Q6 and Q9 read as hedging, but they mark the three places where the answer is an inference or a reconstruction rather than a directly observed artifact. Removing them would make the document look more certain than the evidence supports.
- **Defanged indicators.** URLs are written as `hxxp://10[.]10[.]10[.]5/news[.]php` with the live form in prose, so the file stays safe to paste into a chat or a ticket.
