# Tool 4 Refinement Notes

## Peer Feedback Themes

The peer feedback was positive overall. Reviewers identified two main improvement areas:

1. Repository navigation could be clearer.
2. The rule-based design could miss indirect or unusual privacy-policy wording.

## Accepted Refinements

I accepted the repository discoverability feedback and updated the root README so reviewers can find Tool 4 directly.

I also accepted the feedback about fixed rules. To address this while preserving the tool's offline design, I added more indirect and vague-language rules and added support for optional custom JSON rule files.

## Partially Accepted Feedback

Several reviewers suggested AI, LLM support, or learning-based analysis. I agree this could be useful in future work. I did not add a cloud LLM in this version because the tool is designed to be offline, lightweight, reproducible, and privacy-preserving. Sending privacy notices to a third-party model could create a privacy concern inside a privacy-review tool.

## Deferred Future Work

Future versions could add optional local LLM support, more privacy-law-specific rule profiles, user-maintained rule libraries, confidence scoring for indirect language, and more test cases using real-world privacy notices.

## Version

These refinements were added in version 1.1.0.
