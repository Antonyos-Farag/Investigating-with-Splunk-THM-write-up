<!--
Corrections to a finding need a citation. Prose/typo fixes do not — delete the
evidence section if your change does not touch a finding.
-->

## What kind of change is this?

- [ ] Correction to a finding (an answer, an event field value, an event ID)
- [ ] SPL improvement
- [ ] Prose, typo, or broken anchor
- [ ] Added analysis of an artifact the write-up missed

## Summary

<!-- One or two sentences. -->

## Evidence for any changed finding

<!--
Required if you ticked "Correction to a finding".

- Field name and value as the event records it
- EventID and Channel
- Timestamp, and say whether it is EventTime or UtcTime
- The SPL you ran and the result count

An answer change without this will be closed with a request for evidence, not
rejected — but it will not be merged as-is.
-->

| Field | Value |
| --- | --- |
| EventID | |
| Channel | |
| Hostname | |
| Field | |

**Query:**

```spl

```

**Result count:**

## Checklist

- [ ] `python3 scripts/check-docs.py` passes
- [ ] Question structure preserved (**Objective → Approach → SPL → Evidence → Answer**)
- [ ] No screenshots or `images/` references added
- [ ] Any caveat that no longer applies was updated rather than deleted silently
- [ ] Indicators remain defanged
