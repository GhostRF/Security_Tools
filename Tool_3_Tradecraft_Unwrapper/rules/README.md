# Tradecraft Rule Files

Tradecraft Unwrapper loads behavioral rules from JSON. The bundled default rule
set is `default.json`. A different validated rule file can be supplied with the
`--rules` option.

Each rule includes:

- `rule_id`: Unique identifier
- `title`: Finding title
- `description`: Cautious explanation of the hypothesis
- `severity`: Potential analytical priority
- `confidence`: Rule-defined evidence-strength score from 0 through 100
- `confidence_basis`: Explanation of why the confidence value was selected
- `attack_id`: Optional MITRE ATT&CK technique or sub-technique identifier
- `attack_name`: Optional MITRE ATT&CK name
- `match`: Observable type and values evaluated by the rule

Confidence is not a statistical probability and does not represent the
likelihood that an input is malicious. See `docs/CONFIDENCE_MODEL.md` for the
complete interpretation and scale.

The current engine supports:

- `transform` rules, which match reconstructed transformation names
- `indicator` rules, which match an indicator kind and an exact normalized value

Custom rules must use schema version 1 and pass the tool's rule validation.
