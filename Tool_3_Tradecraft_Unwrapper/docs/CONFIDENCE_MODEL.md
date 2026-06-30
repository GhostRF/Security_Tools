# Confidence Model

Tradecraft Unwrapper uses rule-defined confidence values to communicate the
strength and specificity of the evidence supporting a behavioral hypothesis.

## What Confidence Means

Confidence represents how strongly the observed evidence supports the stated
behavioral or MITRE ATT&CK hypothesis.

Confidence does not represent:

- The probability that the input is malicious
- A statistical probability derived from a trained model
- A malware verdict
- Proof that an ATT&CK technique was executed
- The severity or potential impact of the behavior

The tool performs static analysis and cannot determine intent solely from an
encoded transformation, command name, or dual-use utility.

## Confidence Scale

| Score | Interpretation |
|---|---|
| 90-100 | High confidence. A direct and specific observable strongly supports the behavioral hypothesis. |
| 75-89 | Moderate confidence. A direct dual-use artifact supports the hypothesis, but context and intent remain ambiguous. |
| 50-74 | Contextual confidence. An indirect or broad transformation supports the hypothesis, but benign explanations are common. |
| 0-49 | Low confidence. Weak or experimental evidence. Default rules should generally avoid this range. |

## How Scores Are Assigned

Version 0.1.0 uses fixed, rule-defined confidence values. Each rule author
assigns a confidence value based on the specificity of the observable used by
the rule.

Examples:

- An exact PowerShell or cmd.exe command indicator is assigned 90 because the
  interpreter reference is directly observable.
- An exact reference to mshta, regsvr32, or rundll32 is assigned 85 because the
  named utility is directly observable, but the utility is dual-use and the
  analyst must determine intent.
- Encoding or compression is assigned 70 because a transformation was directly
  reconstructed, but encoding and compression are also common in legitimate
  software and administration.

The engine does not currently increase or decrease confidence based on the
number of matches. Multiple matches add evidence and stage references, but the
rule's configured confidence value remains unchanged.

## Confidence Versus Severity

Confidence and severity are separate concepts.

- Confidence describes the strength of the evidence supporting a hypothesis.
- Severity describes the potential analytical priority of the observed
  behavior.

A finding may have high confidence but only medium severity, such as a direct
observation of a legitimate administrative interpreter.

## Analyst Responsibility

All findings are hypotheses requiring analyst review. ATT&CK mappings indicate
that the evidence is consistent with a technique description; they do not prove
that an adversary used the technique or that the input is malicious.
