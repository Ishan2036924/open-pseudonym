# Offline benchmark

Items: 120 generated (seed 20261105), 14 hand-written.
Profile for detection: strict. No model involved; costs nothing.

## Detection, generated set

| Type | Gold | Recall | Found | Precision |
|---|---|---|---|---|
| ADDRESS | 60 | 100% | 60 | 100% |
| CARD | 30 | 100% | 30 | 100% |
| DATE | 60 | 100% | 60 | 100% |
| EMAIL | 90 | 100% | 90 | 100% |
| MONEY | 90 | 100% | 90 | 100% |
| ORG | 30 | 100% | 30 | 100% |
| OTP | 30 | 100% | 30 | 100% |
| PERSON | 210 | 100% | 210 | 100% |
| PHONE | 60 | 100% | 60 | 100% |

## Detection, hand-written set

| Type | Gold | Recall | Found | Precision |
|---|---|---|---|---|
| ADDRESS | 1 | 100% | 1 | 100% |
| API_KEY | 1 | 100% | 1 | 100% |
| BANK_ACCOUNT | 1 | 100% | 1 | 100% |
| DATE | 4 | 100% | 4 | 100% |
| EMAIL | 2 | 100% | 2 | 100% |
| IBAN | 1 | 100% | 1 | 100% |
| IP_ADDRESS | 1 | 100% | 1 | 100% |
| MONEY | 2 | 100% | 2 | 100% |
| OTP | 2 | 100% | 2 | 100% |
| PASSWORD | 1 | 100% | 1 | 100% |
| PERSON | 7 | 86% | 6 | 100% |
| PHONE | 1 | 100% | 1 | 100% |
| ROUTING | 1 | 100% | 1 | 100% |
| SSN | 1 | 100% | 1 | 100% |
| URL | 1 | 100% | 1 | 100% |

## Leak rate (planted values the profile should hide that still reach the model)

| Profile | Generated | Hand-written |
|---|---|---|
| strict | 0/570 (0.0%) | 1/25 (4.0%) |
| draft_reply | 0/540 (0.0%) | 1/25 (4.0%) |
| summarize | 0/570 (0.0%) | 1/25 (4.0%) |
| secrets_only | 0/60 (0.0%) | 0/8 (0.0%) |
| strict + the app's contacts | 0/570 (0.0%) | 0/25 (0.0%) |

## Round trip and speed

- restore(mask(x)) == x: 134/134
- streamed restore == whole restore: 134/134
- mask: median 0.38 ms, p95 0.60 ms per item
- restore: median 0.12 ms per item
