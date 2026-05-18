# AI Usage Disclosure

AI assistance was used during the planning, documentation, troubleshooting, and refinement of this security tool.

AI was used to help with:

- Brainstorming the initial tool concept and feature set.
- Drafting and improving README documentation.
- Drafting dataset setup guidance.
- Troubleshooting parser behavior during public dataset testing.
- Refining explanations of ATT&CK mapping, correlation logic, limitations, and responsible use.
- Reviewing command-line workflow and GitHub repository cleanup steps.

All final code, documentation, testing decisions, and repository changes were reviewed by the project author before inclusion.

## Human Validation Performed

The final tool was validated through:

- Python syntax checking with `python -m py_compile`.
- Synthetic sample testing using the included files in the `samples/` directory.
- Public dataset testing using an OTRF Mordor dataset.
- Manual review of generated outputs, including JSON, CSV, DOT, HTML, and validation notes.
- Manual review of ATT&CK technique IDs and names for consistency.
- Repository cleanup to remove generated output, local datasets, virtual environments, placeholder files, and duplicate documentation.

## Important Note

AI-generated suggestions were not accepted automatically. Suggestions were reviewed, modified, tested, and validated before being included in the project.
