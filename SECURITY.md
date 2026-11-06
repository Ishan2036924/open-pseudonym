# Security

This project protects personal data, so reports are very welcome.

**Please do not open a public issue for a vulnerability.** Email **support@atlasiw.com** with "Open Pseudonym
security" in the subject, or use GitHub's private "Report a vulnerability" button on this repository if it is shown.
Include:

- what breaks: a real value that reaches the model when it should not, a handle filled somewhere its binding forbids,
  a receipt that verifies when it should not, two SDKs that disagree, a crash;
- a minimal input or script that shows it;
- which SDK and commit.

You will get an answer within 3 working days. Fixes land with a vector or test that fails before the fix, in both
SDKs, and the report is credited in the changelog unless you ask otherwise.

Known limits that are not vulnerabilities (they are documented): values no detector finds are not hidden;
re-identification from context is reduced, not prevented; text inside images is out of scope for v0.1.
