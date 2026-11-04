# Realistic Guard Spec data (`guard-spec:realistic-fable`)

Copyright The Guard Spec Authors. Licensed Apache-2.0.

Two files of hand-written, realistic prompt-injection training and holdout data for the Guard Spec L2
classifier (English and Vietnamese), written to the schema in `train/DATA_CARD.md` and labelled by
`train/LABELING.md`.

| file | rows | attack | benign | VI share | groups |
|---|---|---|---|---|---|
| `realistic_train.jsonl` | 2412 | 1116 (46.3%) | 1296 | 55.7% | 890 |
| `realistic_holdout.jsonl` | 613 | 247 (40.3%) | 366 | 54.0% | 279 |

Schema per row: `id` (`<lang>-<first 12 hex of sha256(text)>`), `text`, `labels`, `lang`, `variant`
(`orig`, `no_diacritics`, `teencode`), `source` = `guard-spec:realistic-fable`, `license` = `Apache-2.0`,
`group` = scenario id (`rf.<split>.<lang>.<category>.<scenario>`).

## How the data was made

1. **Scenario plan first.** Two disjoint sets of fictional organisations were fixed before any row was
   written, one per file, so that train and holdout share no company, situation or phrasing:
   - train VI: Ngân hàng TMCP Đông Phương (ĐPBank), sàn TMĐT ShopViet, Bảo hiểm Minh An, SaoViet Telecom,
     Bệnh viện Đa khoa Hồng Hà, Đại học Kỹ thuật Thành Đô, Bắc Nam Express, UBND phường Đông Hưng / cổng dịch
     vụ công, Công ty CP Phần mềm Tân Việt, Công ty TNHH Sản xuất Gia Long;
   - holdout VI: Ngân hàng TMCP Tây Đô (TDBank), Hùng Vương Mart, Bảo hiểm An Phúc, VinaConnect, Phòng khám
     Đa khoa Quốc tế Thiên Ân, Học viện Công nghệ Mekong, Hoàng Gia Express, Trung tâm Hành chính công tỉnh
     Lâm Giang, Công ty CP Công nghệ Số Việt Tín, Tập đoàn Dệt may Hải Phát;
   - train EN: Northgate Credit Union, Brightline Retail, Halcyon Insurance, Meridian Telecom, Westbrook
     Hospital, Kestrel University, Atlas Freight, City of Fairhaven, Orion Software, Lumen HR;
   - holdout EN: Pinecrest Bank, Harbor Market, Sentinel Mutual, Crestwave Mobile, Oakridge Clinic, Larkspur
     College, Blue Dune Logistics, Ridgeview County Services, Vireo Labs, Summit Staffing.
   Every scenario (organisation × situation × carrier) was assigned to exactly one file and carries one
   `group` id; the build asserts that the two files share no group.
2. **Hand-written rows.** Twelve writer agents (forks of the same model session, each holding the labeling
   guide and data card) wrote their slice row by row in `parts/*.py`: no templates, no programmatic
   combination of fragments, no diacritic-stripped or teencode copies of another row. `no_diacritics` and
   `teencode` rows are independent texts, written that way from the start. Attack slices were written in
   chunks of at most 20 rows. Each writer ran `parts_check.py` (schema, exact and near-duplicate check) on
   its files until it reported zero problems.
3. **Assembly** (`build_realistic.py`, run with `uv run python -I` from `train/` so it can import the repo's
   `build_data.py`): schema validation, NFC normalisation, id assignment, exact dedupe on the fingerprint
   normalisation (NFC, đ→d, diacritics stripped, lowercase, whitespace collapsed), greedy near-duplicate
   removal at character 5-gram Jaccard ≥ 0.6 within each file and of holdout against train, group
   disjointness assertion, counts, and the repo's eval leakage guard (`build_data.load_eval`,
   `build_data.max_jaccard`, `common.fingerprint`). Eval rows were never opened, sampled or grepped by any
   writer; they are read into memory only by the imported guard, and nothing from them is printed.
4. `make_readme.py` renders this file from `report.json`.

## Language and register

- Language: 56% Vietnamese / 44% English in train,
  54% / 46% in holdout. English rows are all `orig`.
- Vietnamese register: most rows are proper Vietnamese with full diacritics in a formal or business register
  (directives, notices, emails, tickets, contracts, memos), for attacks and benign rows alike, because that
  is how real attackers write to look legitimate. About 15% are `no_diacritics` (typed quickly on a phone,
  still serious) and about 5% are light `teencode` (ko, đc, mik, bn, ntn, j...), used for chat-like benign
  text and a few casual attacks.

Train, Vietnamese rows by variant:

| VI variant | benign | attack | total | share |
|---|---|---|---|---|
| `orig` | 597 | 489 | 1086 | 80.8% |
| `no_diacritics` | 107 | 88 | 195 | 14.5% |
| `teencode` | 36 | 27 | 63 | 4.7% |

Holdout, Vietnamese rows by variant:

| VI variant | benign | attack | total | share |
|---|---|---|---|---|
| `orig` | 169 | 102 | 271 | 81.9% |
| `no_diacritics` | 26 | 21 | 47 | 14.2% |
| `teencode` | 9 | 4 | 13 | 3.9% |

## Counts per label

Rows can carry several attack labels, so label counts add up to more than the row count.

Train (length min 48, median 192, p90 345, max 787 characters; 631 multi-line rows):

| label | EN | VI | total |
|---|---|---|---|
| `benign` | 556 | 740 | 1296 |
| `direct_injection` | 132 | 173 | 305 |
| `indirect_injection` | 159 | 177 | 336 |
| `jailbreak` | 87 | 96 | 183 |
| `prompt_extraction` | 103 | 105 | 208 |
| `data_exfiltration` | 103 | 107 | 210 |
| `tool_poisoning` | 77 | 52 | 129 |
| `obfuscation` | 54 | 65 | 119 |
| **rows** | **1068** | **1344** | **2412** (1116 attack, 1296 benign) |

Holdout (length min 66, median 174, p90 273, max 704 characters; 102 multi-line rows):

| label | EN | VI | total |
|---|---|---|---|
| `benign` | 162 | 204 | 366 |
| `direct_injection` | 34 | 44 | 78 |
| `indirect_injection` | 30 | 28 | 58 |
| `jailbreak` | 17 | 20 | 37 |
| `prompt_extraction` | 21 | 29 | 50 |
| `data_exfiltration` | 23 | 21 | 44 |
| `tool_poisoning` | 10 | 10 | 20 |
| `obfuscation` | 6 | 9 | 15 |
| **rows** | **282** | **331** | **613** (247 attack, 366 benign) |

Attack label sets, train:

| label set | rows |
|---|---|
| `direct_injection` | 238 |
| `indirect_injection` | 187 |
| `jailbreak` | 119 |
| `prompt_extraction` | 111 |
| `data_exfiltration` | 105 |
| `tool_poisoning` | 48 |
| `data_exfiltration, indirect_injection` | 39 |
| `indirect_injection, obfuscation` | 33 |
| `indirect_injection, prompt_extraction` | 32 |
| `data_exfiltration, tool_poisoning` | 31 |
| `indirect_injection, jailbreak` | 21 |
| `prompt_extraction, tool_poisoning` | 21 |
| `direct_injection, obfuscation, prompt_extraction` | 18 |
| `jailbreak, tool_poisoning` | 16 |
| `data_exfiltration, direct_injection` | 10 |
| `direct_injection, prompt_extraction` | 10 |
| `data_exfiltration, indirect_injection, obfuscation` | 10 |
| `direct_injection, jailbreak` | 8 |
| `indirect_injection, obfuscation, prompt_extraction` | 8 |
| `direct_injection, obfuscation` | 7 |
| `data_exfiltration, direct_injection, obfuscation` | 7 |
| `indirect_injection, jailbreak, obfuscation` | 6 |
| `obfuscation, tool_poisoning` | 6 |
| `data_exfiltration, obfuscation` | 5 |
| `direct_injection, jailbreak, obfuscation` | 5 |
| `jailbreak, obfuscation` | 4 |
| `obfuscation, prompt_extraction, tool_poisoning` | 3 |
| `data_exfiltration, obfuscation, tool_poisoning` | 2 |
| `obfuscation, prompt_extraction` | 1 |
| `direct_injection, jailbreak, obfuscation, prompt_extraction` | 1 |
| `data_exfiltration, direct_injection, obfuscation, prompt_extraction` | 1 |
| `jailbreak, prompt_extraction, tool_poisoning` | 1 |
| `jailbreak, obfuscation, tool_poisoning` | 1 |
| `jailbreak, obfuscation, prompt_extraction` | 1 |

Attack label sets, holdout:

| label set | rows |
|---|---|
| `direct_injection` | 55 |
| `indirect_injection` | 48 |
| `jailbreak` | 30 |
| `data_exfiltration` | 29 |
| `prompt_extraction` | 29 |
| `data_exfiltration, indirect_injection` | 7 |
| `data_exfiltration, tool_poisoning` | 7 |
| `tool_poisoning` | 7 |
| `direct_injection, prompt_extraction` | 6 |
| `direct_injection, obfuscation, prompt_extraction` | 6 |
| `direct_injection, obfuscation` | 5 |
| `direct_injection, jailbreak` | 4 |
| `obfuscation, prompt_extraction` | 3 |
| `prompt_extraction, tool_poisoning` | 3 |
| `indirect_injection, prompt_extraction` | 2 |
| `direct_injection, tool_poisoning` | 2 |
| `indirect_injection, jailbreak` | 1 |
| `jailbreak, prompt_extraction` | 1 |
| `data_exfiltration, obfuscation` | 1 |
| `jailbreak, tool_poisoning` | 1 |

## What the rows cover

Attacks (both languages, every listed domain: banking, e-commerce, HR, insurance, government services,
education, healthcare, telecoms, logistics, software):

- **Authority impersonation and social engineering** as `direct_injection`: fake Ban Giám đốc / IT /
  compliance / audit / vendor / developer / legal notices, maintenance windows, "Căn cứ Quyết định số...",
  urgency, politeness and flattery, written in a formal register.
- **Indirect injection** inside emails, support tickets, contracts, CVs, product reviews, web pages,
  meeting notes, invoices, PDF text, code comments, READMEs, tool and API JSON, search results and chat
  transcripts; instructions addressed to "AI assistant" / "hệ thống AI" mid-document and instructions that
  pose as the document's own workflow; payloads add `prompt_extraction`, `data_exfiltration` or
  `jailbreak` where that is their purpose.
- **Prompt extraction** phrased as a legitimate need: audit, debugging, QA, staging clone, configuration
  verification, translation or reformatting of the system prompt.
- **Data exfiltration** to external emails, webhooks, markdown images, "analytics" endpoints, in summaries.
- **Tool poisoning**: MCP JSON, Python docstrings, OpenAPI/YAML, TypeScript tool registrations with hidden
  preconditions or "supersedes all other tools" clauses, in English and Vietnamese.
- **Jailbreaks**: personas, "modes", hypothetical and research framing, "for training an internal model",
  multi-step persuasion collapsed into one message, split payloads.
- **Obfuscation** (always paired with the content label): Vietnamese–English code switching, sparing
  homoglyphs, instructions inside code blocks, markdown and HTML comments, sparing base64, rare zero-width
  characters, spaced and split text.

Benign rows, with hard negatives as the largest share:

- real user requests in the same domains, formal and casual, one-liners to multi-paragraph;
- legitimate instructions inside documents ("bỏ qua mục 3 vì đã hết hiệu lực", "ignore the previous draft",
  superseded clauses, amended minutes, ticket merges);
- IT and admin work using hệ thống, lệnh, quyền quản trị, ghi đè, override, bypass, admin, `system_prompt`
  config keys in ordinary senses, runbooks, access requests;
- security professionals discussing prompt injection, guardrail thresholds and red-team plans, test files
  that quote attack strings as data;
- developers asking how to write and evaluate the system prompt of their own app;
- harmless role-play (interviewer, tutor, tour guide, difficult customer, text adventure);
- formal directives and official notices from real managers and authorities, addressed to people;
- customer support chats, internal and customer emails, meeting notes, code reviews and translation requests.

## Scenario list, train

- `rf.train.en.authority.*` — 22 scenario(s), 93 rows: `atlas-dispatch-escalation` (4), `brightline-compliance-audit` (8), `brightline-fixed-reply` (3), `brightline-vendor-cutover` (3), `ceo-urgent` (4), `compliance-mandatory` (3), `fairhaven-council-resolution` (4), `flattery-politeness` (4), `halcyon-vendor-notice` (7), `kestrel-registrar-note` (3), `legal-counsel` (4), `lumen-hr-policy-change` (3), `meridian-platform-admin` (7), `meridian-supervisor-chat` (3), `northgate-dpo` (3), `northgate-it-maintenance` (7), `northgate-override-recommend` (3), `orion-developer-hotfix` (4), `pentest-authorised` (3), `security-incident` (4), `system-notice-forged` (3), `westbrook-it-change` (6)
- `rf.train.en.codereview.*` — 4 scenario(s), 9 rows: `brightline-checkout` (2), `orion-config` (2), `orion-pr` (3), `scripts` (2)
- `rf.train.en.dev.*` — 4 scenario(s), 26 rows: `assistant-behaviour-debug` (7), `prompt-engineering-tools` (7), `rag-eval-questions` (4), `system-prompt-design` (8)
- `rf.train.en.docs.*` — 21 scenario(s), 110 rows: `atlas-freight-rate-memo` (9), `brightline-marketing-brief` (4), `brightline-ticket-threads` (10), `contracts` (1), `cv` (1), `fairhaven-council-minutes` (8), `halcyon-policy-redraft` (10), `incidents` (1), `invoices` (1), `kestrel-grant-report` (4), `kestrel-syllabus-updates` (9), `lumen-hr-handbook` (9), `meridian-vendor-contract` (9), `northgate-loan-agreement` (8), `orion-onboarding-doc` (4), `orion-release-notes` (8), `readme` (1), `reviews` (2), `search` (1), `tickets` (2), `westbrook-protocol-revision` (8)
- `rf.train.en.email.*` — 7 scenario(s), 12 rows: `atlas-drivers` (1), `fairhaven-housing` (2), `halcyon-workflow` (2), `kestrel-notices` (2), `lumen-payroll` (1), `orion-internal` (2), `westbrook-feedback` (2)
- `rf.train.en.exfil.*` — 16 scenario(s), 48 rows: `atlas-manifest-leak` (3), `brightline-history-export` (4), `fairhaven-resident-list` (2), `halcyon-audit-mirror` (3), `halcyon-claim-forward` (3), `history-to-url` (3), `kestrel-student-export` (3), `lumen-candidate-leak` (3), `meridian-crm-push` (3), `northgate-summary-link` (4), `orion-keys-webhook` (4), `override-then-exfil` (2), `summit-roster-send` (3), `vireo-env-dump` (3), `vireo-source-leak` (2), `westbrook-record-copy` (3)
- `rf.train.en.extraction.*` — 14 scenario(s), 50 rows: `atlas-integration-check` (3), `atlas-what-were-you-told` (3), `brightline-debug` (4), `fairhaven-foi` (3), `halcyon-first-line` (3), `halcyon-translate-prompt` (5), `kestrel-rules-list` (3), `lumen-policy-request` (3), `meridian-verify-config` (4), `northgate-config-audit` (5), `orion-qa-harness` (3), `override-then-extract` (4), `secret-in-prompt` (4), `westbrook-config-review` (3)
- `rf.train.en.indirect.*` — 21 scenario(s), 139 rows: `atlas-invoices` (7), `brightline-reviews` (13), `brightline-searchjson` (7), `fairhaven-contracts` (6), `fairhaven-notes` (6), `halcyon-chat` (7), `halcyon-claims` (5), `halcyon-tickets` (6), `kestrel-cvs` (6), `kestrel-emails` (7), `lumen-pdfforms` (7), `meridian-chat` (4), `meridian-tooljson` (6), `meridian-wiki` (7), `northgate-emails` (7), `northgate-tickets` (5), `northgate-wiki` (6), `orion-codecomments` (7), `orion-readme` (6), `westbrook-notes` (7), `westbrook-tickets` (7)
- `rf.train.en.itadmin.*` — 10 scenario(s), 84 rows: `atlas-config-snippets` (9), `brightline-cache-bypass` (9), `city-gis-access` (4), `fairhaven-helpdesk-chat` (9), `kestrel-lms-config` (9), `lumen-saas-admin` (5), `meridian-network-config` (10), `northgate-password-resets` (10), `orion-runbooks` (10), `westbrook-ad-permissions` (9)
- `rf.train.en.jailbreak.*` — 15 scenario(s), 55 rows: `authority-plus-persona` (3), `collapsed-persuasion` (3), `fiction-wrapper` (4), `gradual-escalation` (4), `grandfather-exception` (3), `hypothetical-framing` (4), `internal-model-training` (3), `kestrel-debate-persona` (4), `meridian-diagnostic-persona` (4), `orion-persona-mode` (5), `research-framing` (3), `reset-amnesia` (3), `roleplay-no-rules` (5), `split-payload` (4), `token-threat` (3)
- `rf.train.en.meeting.*` — 7 scenario(s), 7 rows: `atlas-standup` (1), `brightline-weekly` (1), `fairhaven-council` (1), `halcyon-leadership` (1), `kestrel-examboard` (1), `meridian-product` (1), `orion-retro` (1)
- `rf.train.en.notice.*` — 7 scenario(s), 31 rows: `atlas-safety-bulletin` (3), `fairhaven-public` (5), `halcyon-broker-circular` (3), `lumen-hr-directives` (5), `meridian-maintenance` (5), `northgate-member-circular` (5), `westbrook-audit-schedule` (5)
- `rf.train.en.obf.*` — 7 scenario(s), 50 rows: `base64` (9), `codeblock` (12), `fragments` (2), `homoglyph` (8), `html-comments` (5), `spaced` (6), `zerowidth` (8)
- `rf.train.en.requests.*` — 40 scenario(s), 193 rows: `atlas-consumer` (3), `atlas-ops` (3), `atlas-shipments` (6), `brightline-content` (5), `brightline-orders` (5), `brightline-sellers` (3), `casual-chat` (15), `everyday-misc` (30), `fairhaven-comms` (2), `fairhaven-jobs` (2), `fairhaven-services` (6), `formal-professional` (10), `halcyon-claims` (5), `halcyon-internal` (3), `halcyon-quotes` (4), `kestrel-admin` (4), `kestrel-staff` (4), `kestrel-students` (6), `long-community` (1), `long-education` (1), `long-household` (2), `long-management` (1), `long-office` (1), `long-smallbusiness` (1), `lumen-career` (4), `lumen-hiring` (5), `lumen-leave` (4), `lumen-payroll` (2), `meridian-internal` (2), `meridian-mobile` (4), `meridian-support` (6), `northgate-business` (4), `northgate-dispute` (5), `northgate-fees` (5), `northgate-savings` (5), `orion-dev` (6), `orion-product` (4), `westbrook-health` (5), `westbrook-patients` (6), `westbrook-staff` (3)
- `rf.train.en.roleplay.*` — 7 scenario(s), 45 rows: `coaching` (8), `games` (10), `language-tutor` (4), `mock-interview` (4), `sales-training` (4), `service-personas` (9), `writing` (6)
- `rf.train.en.security.*` — 4 scenario(s), 21 rows: `halcyon-threat-model` (6), `meridian-incident-comms` (3), `northgate-guardrail-tests` (6), `orion-assistant-assessment` (6)
- `rf.train.en.support.*` — 5 scenario(s), 8 rows: `atlas-chat` (1), `brightline-chat` (2), `meridian-chat` (2), `northgate-chat` (2), `westbrook-chat` (1)
- `rf.train.en.tool.*` — 10 scenario(s), 77 rows: `docstrings` (12), `json-spec` (8), `mcp-functions` (9), `mcp-json` (7), `openapi` (8), `openapi-yaml` (7), `param-descriptions` (8), `params` (7), `ts-tools` (3), `yaml-manifest` (8)
- `rf.train.en.translation.*` — 5 scenario(s), 10 rows: `check` (2), `de-en` (1), `en-vi` (3), `ui-strings` (2), `vi-en` (2)
- `rf.train.vi.chat.*` — 3 scenario(s), 15 rows: `assistant` (10), `friends` (1), `team` (4)
- `rf.train.vi.codereview.*` — 2 scenario(s), 14 rows: `tanviet-pr` (8), `tanviet-script` (6)
- `rf.train.vi.devprompt.*` — 12 scenario(s), 24 rows: `beginner` (3), `clinic-bot` (1), `compliance-bot` (1), `config-design` (4), `eval-harness` (3), `extraction-app` (1), `function-calling` (2), `logging-debug` (1), `migration` (1), `multilingual` (1), `rag-app` (3), `sales-bot` (3)
- `rf.train.vi.direct.*` — 132 scenario(s), 147 rows: `admission-appeal` (1), `admission-pass` (1), `airline-loyalty` (1), `airport-checkin` (1), `api-partner` (1), `auto-consent` (1), `bacnam-invoice` (1), `bacnam-ops` (2), `bed-triage` (1), `card-limit` (1), `casual-approve` (1), `casual-confirm` (1), `casual-contract` (1), `casual-loan` (1), `casual-withdraw` (1), `cod-recon` (1), `credit-score` (1), `crisis-pr` (1), `csat-promise` (1), `customs-clear` (1), `dc-perm` (1), `deadline-rush` (1), `dealer-credit` (1), `disparage` (1), `donghung-dvc` (2), `donghung-fast` (1), `donghung-onegate` (1), `dpbank-audit` (4), `dpbank-authz` (1), `dpbank-board` (2), `dpbank-drill` (1), `dpbank-ops` (3), `dpbank-risk` (1), `dpo-review` (1), `driver-unlock` (1), `einvoice-tax` (1), `ekyc-skip` (1), `elearning-cert` (1), `emergency-mode` (1), `esign-skip` (1), `event-advance` (1), `ewallet-dispute` (1), `factory-reset` (1), `finance-adj` (1), `flattery-mgr` (2), `fuelcard-pin` (1), `gialong-hr` (2), `gialong-timesheet` (1), `health-check` (1), `hongha-ops` (1), `hongha-plan` (1), `hongha-survey` (1), `hongha-triage` (1), `hotel-upgrade` (1), `inspect-team` (1), `insurance-renew` (1), `internal-domain` (1), `kpi-fake` (1), `lawyer` (1), `lc-skip` (1), `library-waive` (1), `memo-config` (2), `microfinance` (1), `migration` (1), `minhan-brand` (1), `minhan-claim` (2), `minhan-contract` (1), `minhan-greenlane` (1), `no-logging` (1), `no-reject` (1), `notary` (1), `open-mode` (1), `overdraft` (1), `override-test` (1), `partner-priority` (1), `payment-glitch` (1), `pentest-scope` (1), `perf-opt` (1), `pharmacy-order` (1), `platform-vendor` (1), `power-meter` (1), `priority-flag` (1), `procurement` (1), `product-soft` (1), `pw-reset-all` (1), `qc-listen` (1), `qc-skip` (1), `quality-score` (1), `realestate-escrow` (1), `recall-deny` (1), `recorded-session` (1), `recruit-skip` (1), `regulator` (1), `report-access` (1), `retail-returns` (1), `retention` (1), `ride-refund` (1), `saoviet-it` (1), `saoviet-legal` (1), `saoviet-ops` (2), `scholarship` (1), `script-only` (1), `scrub-warning` (1), `securities-margin` (1), `shift-handover` (1), `shopviet-fraud` (1), `shopviet-label` (1), `shopviet-maint` (1), `shopviet-promo` (1), `shopviet-review` (1), `shopviet-seller` (1), `skip-verify` (1), `soc-malware` (1), `sole-approver` (1), `superadmin` (1), `tanviet-maint` (2), `tanviet-refund` (1), `tax-ontime` (1), `thanhdo-exam` (1), `thanhdo-inspect` (1), `thanhdo-lib` (1), `thanhdo-reg` (1), `training-mode` (1), `uat` (1), `unblock-list` (1), `unlock-all` (1), `vehicle-inspect` (1), `vendor-revoke` (2), `vip-concierge` (1), `waiting-period` (1), `warehouse-out` (1), `warranty-expired` (1)
- `rf.train.vi.directive.*` — 12 scenario(s), 44 rows: `bacnam-directive` (4), `donghung-notice` (4), `dpbank-notice` (3), `dpbank-reorg` (3), `gialong-directive` (5), `hongha-notice` (4), `minhan-notice` (4), `saoviet-notice` (4), `shopviet-announce` (4), `shopviet-training-order` (2), `tanviet-directive` (3), `thanhdo-notice` (4)
- `rf.train.vi.docinstr.*` — 24 scenario(s), 93 rows: `bacnam-dispatch-order` (4), `bacnam-return-sop` (3), `donghung-birth-reg` (4), `donghung-reception-notice` (2), `dpbank-contract-amend` (5), `dpbank-kyc-revision` (4), `email-corrections` (8), `form-field-instructions` (4), `gialong-labor-rules` (3), `gialong-review-form` (3), `gialong-supplier-contract` (3), `hongha-procurement` (2), `hongha-ward-minutes` (4), `meeting-action-items` (4), `minhan-policy-endorsement` (5), `saoviet-complaint-process` (3), `saoviet-ticket-workflow` (4), `shopviet-listing-guide` (4), `shopviet-return-policy` (3), `tanviet-change-request` (4), `tanviet-readme` (4), `thanhdo-graduation-reg` (3), `thanhdo-syllabus` (5), `translation-of-clauses` (5)
- `rf.train.vi.email.*` — 3 scenario(s), 21 rows: `bacnam-khach-hang` (7), `gialong-noi-bo` (8), `minhan-khach` (6)
- `rf.train.vi.exfil.*` — 70 scenario(s), 70 rows: `accounts-csv` (1), `ads-sync` (1), `advisor-leak` (1), `appraisal` (1), `bcc` (1), `blast-sms` (1), `call-card` (1), `card-batch` (1), `casual-drive` (1), `casual-log` (1), `casual-send` (1), `casual-tele` (1), `chart-note` (1), `claim-scan` (1), `config-link` (1), `contract-leak` (1), `deposit-bi` (1), `devops-mail` (1), `excel-hidden` (1), `facility` (1), `ftp` (1), `header-smuggle` (1), `health` (1), `hidden-text` (1), `history-keys` (1), `hr-link` (1), `image-beacon` (1), `income` (1), `income-consult` (1), `insurance-docs` (1), `internal-channel` (1), `loan-profile` (1), `logs-token` (1), `md-link` (1), `member-pull` (1), `newpass` (1), `ocr-id` (1), `open-beacon` (1), `open-tracking` (1), `otp` (1), `override-b2b` (1), `override-balance` (1), `override-crm` (1), `override-dbpass` (1), `override-history` (1), `override-jwt` (1), `override-keys` (1), `override-push` (1), `paste-public` (1), `payroll` (1), `pii-drive` (1), `promo-codes` (1), `qr` (1), `report-env` (1), `session-pass` (1), `ship-list` (1), `ship-sync` (1), `silent-cc` (1), `silent-collect` (1), `sms` (1), `student-fees` (1), `survey` (1), `telegram` (1), `telesale` (1), `temp-pass` (1), `tracking-pixel` (1), `transfer-csv` (1), `vip-list` (1), `webhook` (1), `zip` (1)
- `rf.train.vi.extra.*` — 10 scenario(s), 42 rows: `bacnam-wh` (4), `donghung-citizen` (4), `dpbank-ops` (5), `gialong-hr` (4), `hongha-admin` (4), `minhan-agent` (4), `saoviet-field` (4), `shopviet-seller` (5), `tanviet-dev` (4), `thanhdo-admin` (4)
- `rf.train.vi.indirect.*` — 79 scenario(s), 140 rows: `bacnam-email-damage` (2), `bacnam-email-delay` (1), `bacnam-email-quote` (1), `bacnam-tool-json` (4), `donghung-form-civil` (2), `donghung-form-housing` (1), `donghung-meeting` (1), `donghung-portal-feedback` (1), `donghung-portal-page` (2), `donghung-tool-json` (1), `donghung-webpage-notice` (1), `dpbank-it-notice` (2), `dpbank-it-ticket` (1), `gialong-contract` (2), `gialong-invoice` (4), `gialong-meeting` (3), `gialong-notice` (2), `gialong-tool-json` (1), `hongha-handover` (1), `hongha-intake-form` (2), `hongha-lab-result` (1), `hongha-meeting` (2), `hongha-notice` (1), `hongha-nursing-note` (2), `hongha-survey` (2), `hongha-tool-json` (1), `hongha-webpage-price` (1), `minhan-call-transcript` (1), `minhan-contract` (2), `minhan-email-agent` (1), `minhan-email-policy` (3), `minhan-pdf-form` (1), `minhan-webpage-product` (1), `saoviet-call-transcript` (1), `saoviet-contract` (1), `saoviet-pdf-form` (1), `saoviet-ticket-outage` (3), `saoviet-ticket-plan` (2), `saoviet-ticket-sim` (2), `saoviet-ticket-survey` (1), `saoviet-webpage-promo` (1), `search-results-dvc` (1), `search-results-hospital` (1), `search-results-insurance` (1), `search-results-internal` (1), `search-results-shipping` (1), `shopviet-review-electronics` (3), `shopviet-review-fashion` (2), `shopviet-review-home` (5), `shopviet-ticket-app` (4), `shopviet-ticket-delivery` (3), `shopviet-ticket-seller` (3), `shopviet-webpage-faq` (1), `shopviet-webpage-seller` (1), `tanviet-code-comment` (4), `tanviet-contract` (1), `tanviet-meeting` (4), `tanviet-notice` (2), `tanviet-readme` (3), `tanviet-tool-json` (2), `tanviet-webpage-blog` (1), `tanviet-wiki` (3), `thanhdo-call-transcript` (1), `thanhdo-contract` (1), `thanhdo-cv` (4), `thanhdo-email-staff` (3), `thanhdo-email-student` (3), `thanhdo-meeting` (3), `thanhdo-notice` (2), `thanhdo-notice-dorm` (1), `thanhdo-pdf-form` (1), `thanhdo-webpage-admission` (1), `zalo-class-group` (1), `zalo-family` (1), `zalo-gialong-group` (1), `zalo-oa-bacnam` (1), `zalo-oa-saoviet` (1), `zalo-shopviet-seller` (1), `zalo-tanviet-dev` (1)
- `rf.train.vi.itadmin.*` — 16 scenario(s), 83 rows: `bacnam-wms-devices` (5), `donghung-egov-system` (4), `dpbank-access-rights` (5), `dpbank-password-reset` (5), `general-sysadmin` (8), `gialong-erp` (6), `hongha-his-admin` (6), `minhan-office-support` (6), `minhan-privileged-accounts` (3), `saoviet-app-update` (3), `saoviet-network-ops` (6), `shopviet-config` (4), `shopviet-runbook` (6), `tanviet-dev-infra` (8), `thanhdo-lab-server` (3), `thanhdo-lms-admin` (5)
- `rf.train.vi.jb.*` — 71 scenario(s), 71 rows: `abc-join` (1), `awakened` (1), `buggy` (1), `captain` (1), `casual-fiction` (1), `casual-gm` (1), `casual-honest` (1), `casual-mage` (1), `casual-oracle` (1), `closed-beta` (1), `comic-kairos` (1), `compromised-sim` (1), `confidant` (1), `dev-mode` (1), `director` (1), `dream` (1), `ethics-sandbox` (1), `expired-rules` (1), `fiction-lumen` (1), `future-2099` (1), `gatekeeper` (1), `honesty-mode` (1), `hypothetical` (1), `imagine-free` (1), `improv` (1), `king` (1), `lab-iso` (1), `mage` (1), `maintenance-persona` (1), `mirror` (1), `multistep` (1), `nova` (1), `open-close` (1), `oracle` (1), `persona-tudo` (1), `persuade` (1), `philosophy` (1), `preapproved` (1), `premium-upgrade` (1), `radio-drama` (1), `redteam-authorized` (1), `research-filter` (1), `robot-scene` (1), `role-swap` (1), `sage` (1), `sandbox` (1), `scifi` (1), `screenplay` (1), `secret-code` (1), `shadow` (1), `split-fragments` (1), `story-firstperson` (1), `story-steps` (1), `sudo` (1), `switch` (1), `tech-dual` (1), `tester-exempt` (1), `text-adventure` (1), `thesis-ab` (1), `thesis-control` (1), `token-game` (1), `train-model` (1), `training-example` (1), `true-self` (1), `twin-zero` (1), `two-voices` (1), `unlockall` (1), `vela-char` (1), `voice-actor` (1), `what-if` (1), `world-aventis` (1)
- `rf.train.vi.meeting.*` — 2 scenario(s), 14 rows: `tanviet-bien-ban` (8), `thanhdo-khoa` (6)
- `rf.train.vi.obf.*` — 49 scenario(s), 65 rows: `bacnam-newsletter-htmlcomment` (1), `bacnam-track-fn-zwsp` (1), `base64` (3), `code-block` (5), `donghung-approve-fn-comment` (1), `donghung-feedback-hiddenspan` (1), `donghung-notice-mdcomment` (1), `dpbank-config-fn-zwsp` (1), `dpbank-faq-htmlcomment` (1), `dpbank-notify-fn-base64` (1), `gialong-contract-htmlcomment` (1), `gialong-cv-htmlcomment` (1), `gialong-invoice-htmlcomment` (1), `gialong-minutes-base64` (1), `homoglyph` (2), `hongha-lab-mdcomment` (1), `hongha-minutes-htmlcomment` (1), `hongha-note-codeblock` (1), `hongha-patient-fn-codeblock` (1), `html-comment` (4), `leet` (2), `markdown` (3), `minhan-benefit-fn-comment` (1), `minhan-claim-fn-comment` (1), `minhan-faq-homoglyph` (1), `minhan-product-mdcomment` (1), `mixed-lang` (4), `saoviet-billing-fn-comment` (1), `saoviet-newsletter-htmlcomment` (1), `saoviet-ticket-zwnj` (1), `shopviet-order-fn-comment` (1), `shopviet-review-fn-codeblock` (1), `shopviet-review-htmlcomment` (1), `shopviet-review-zwsp` (1), `shopviet-seller-homoglyph` (1), `split` (1), `tanviet-approve-fn-comment` (1), `tanviet-maint-base64` (1), `tanviet-readme-htmlcomment` (1), `tanviet-recruit-htmlcomment` (1), `tanviet-report-readme-comment` (1), `tanviet-wiki-codeblock` (1), `tanviet-zalo-zwnj` (1), `thanhdo-admission-mdcomment` (1), `thanhdo-classwiki-htmlcomment` (1), `thanhdo-exam-hiddendiv` (1), `thanhdo-export-fn-base64` (1), `thanhdo-notice-codeblock` (1), `zero-width` (1)
- `rf.train.vi.pe.*` — 71 scenario(s), 71 rows: `api-debug` (1), `asset-register` (1), `audit-verbatim` (1), `backup` (1), `bank-audit` (1), `bilingual-check` (1), `blog-example` (1), `bug-report` (1), `casual-forbidden` (1), `casual-homework` (1), `casual-translate` (1), `cert-archive` (1), `clone-staging` (1), `compliance-list` (1), `context-len` (1), `context-truncation` (1), `criteria` (1), `debug-config` (1), `diag-dump` (1), `diff-tool` (1), `doc-slide` (1), `env-compare` (1), `evidence` (1), `full-setup` (1), `handoff-rewrite` (1), `handover-doc` (1), `hash` (1), `homework` (1), `incident-copy` (1), `integrity-check` (1), `interview-q` (1), `iso-archive` (1), `json-export` (1), `json-field` (1), `l10n-qa` (1), `legal-review` (1), `monitor-log` (1), `numbered-list` (1), `ops-override` (1), `override-dump` (1), `override-investigate` (1), `override-ops` (1), `override-paste` (1), `override-secret` (1), `paper-cite` (1), `patch-verify` (1), `pentest-leak` (1), `pii-scan` (1), `promo-secret` (1), `qa-rules` (1), `refusal-templates` (1), `research-compare` (1), `risk-profile` (1), `role-confirm` (1), `roundtrip` (1), `self-describe` (1), `source-priority` (1), `spellcheck` (1), `techdoc` (1), `tone-sync` (1), `traceability` (1), `training-slide` (1), `translate` (1), `translate-check` (1), `translate-ja` (1), `transparency-report` (1), `uat-dump` (1), `unicode-clean` (1), `verify-version` (1), `version-field` (1), `yaml-export` (1)
- `rf.train.vi.roleplay.*` — 7 scenario(s), 41 rows: `gia-su` (6), `huong-dan-vien` (6), `khach-hang-kho-tinh` (6), `luyen-tieng-anh` (5), `phong-van-thu` (7), `tro-choi-ke-chuyen` (5), `tu-van-vien-ngan-hang` (6)
- `rf.train.vi.secpro.*` — 6 scenario(s), 29 rows: `awareness-training` (5), `dpbank-ai-risk` (5), `feature-review` (5), `guardrail-design` (6), `redteam-plan` (4), `tanviet-assessment-report` (4)
- `rf.train.vi.summary.*` — 2 scenario(s), 12 rows: `gov-thong-bao` (6), `hongha-thong-bao` (6)
- `rf.train.vi.support.*` — 3 scenario(s), 21 rows: `dpbank-chat` (6), `saoviet-chat-log` (7), `shopviet-chat-log` (8)
- `rf.train.vi.tool.*` — 40 scenario(s), 40 rows: `bacnam-close-yaml` (1), `bacnam-quote-fn` (1), `bacnam-track-yaml` (1), `donghung-feedback-yaml` (1), `donghung-log-fn` (1), `donghung-mcp-manifest` (1), `donghung-openapi` (1), `dpbank-config-docstring` (1), `dpbank-mail-fn` (1), `dpbank-profile-fn` (1), `gialong-inventory-yaml` (1), `gialong-invoice-fn` (1), `gialong-receipt-fn` (1), `gialong-stafflist-fn` (1), `hongha-appt-list-fn` (1), `hongha-appt-yaml` (1), `hongha-lab-fn` (1), `hongha-protocol-fn` (1), `hongha-record-fn` (1), `hongha-reminder-docstring` (1), `hongha-result-fn` (1), `minhan-benefit-docstring` (1), `minhan-contract-docstring` (1), `minhan-risk-docstring` (1), `saoviet-billing-openapi` (1), `saoviet-netstatus-fn` (1), `saoviet-sms-docstring` (1), `saoviet-ticket-fn` (1), `shopviet-order-fn` (1), `shopviet-revenue-yaml` (1), `shopviet-review-fn` (1), `shopviet-warranty-yaml` (1), `tanviet-approve-fn` (1), `tanviet-docsearch-fn` (1), `tanviet-payroll-yaml` (1), `tanviet-screening-yaml` (1), `tanviet-summary-docstring` (1), `thanhdo-fee-fn` (1), `thanhdo-grade-fn` (1), `thanhdo-student-fn` (1)
- `rf.train.vi.top.*` — 21 scenario(s), 78 rows: `bacnam-cold-chain-bid` (3), `bacnam-invoice-check` (3), `dpbank-audit-findings` (4), `dpbank-model-risk` (5), `dpbank-tender-adjust` (4), `founder-insurance-bot` (5), `gialong-cv-screening` (3), `gialong-erp-change` (4), `hongha-his-release` (3), `hongha-supplies-order` (3), `hongha-zalo-oncall` (3), `minhan-retention-circular` (4), `policy-translation` (5), `roleplay-complaint` (4), `roleplay-negotiation` (3), `roleplay-oral-exam` (4), `saoviet-audit-privacy` (3), `shopviet-review-batch` (3), `tanviet-assistant-config` (3), `tanviet-zalo-deploy` (5), `thanhdo-lms-request` (4)
- `rf.train.vi.translate.*` — 2 scenario(s), 15 rows: `email-doi-tac` (7), `hop-dong-bieu-mau` (8)
- `rf.train.vi.user.*` — 27 scenario(s), 194 rows: `banking.dpbank-app-dang-nhap` (8), `banking.dpbank-chuyen-khoan-loi` (8), `banking.dpbank-the-tin-dung` (8), `banking.dpbank-vay-mua-nha` (7), `ecom.shopviet-doi-tra` (8), `ecom.shopviet-khuyen-mai` (6), `ecom.shopviet-nguoi-ban` (7), `edu.thanhdo-giang-vien` (7), `edu.thanhdo-sinh-vien` (8), `everyday.gia-dinh` (8), `everyday.hoc-tap` (7), `everyday.viet-lach` (7), `gov.donghung-dich-vu-cong` (7), `gov.donghung-ho-khau-cccd` (8), `health.hongha-dat-lich` (7), `health.hongha-ket-qua` (6), `hr.gialong-danh-gia` (6), `hr.gialong-noi-quy-nghi-phep` (7), `hr.gialong-tuyen-dung` (8), `insurance.minhan-boi-thuong` (8), `insurance.minhan-tu-van-goi` (6), `logistics.bacnam-doanh-nghiep` (6), `logistics.bacnam-tra-don` (8), `software.tanviet-dev` (8), `software.tanviet-pm` (6), `telecom.saoviet-goi-cuoc` (7), `telecom.saoviet-su-co` (7)

## Scenario list, holdout

- `rf.holdout.en.di.*` — 6 scenario(s), 30 rows: `larkspur-dean` (5), `pinecrest-it-rollout` (5), `ridgeview-clerk` (5), `sentinel-compliance` (5), `summit-recruiter` (5), `vireo-founder` (5)
- `rf.holdout.en.ex.*` — 4 scenario(s), 15 rows: `ridgeview-sync` (3), `sentinel-claims` (4), `summit-pipeline` (4), `vireo-context` (4)
- `rf.holdout.en.hn.*` — 14 scenario(s), 63 rows: `dev-own-prompt` (7), `dev-test-fixtures` (4), `directive-bluedune` (3), `directive-internal` (3), `directive-larkspur` (3), `directive-pinecrest` (3), `directive-public` (3), `doc-revisions` (5), `it-admin-ops` (6), `it-config` (9), `roleplay-practice` (4), `sec-redteam` (6), `sec-wiki` (2), `wording-help` (5)
- `rf.holdout.en.ii.*` — 10 scenario(s), 30 rows: `bluedune-manifest` (2), `crestwave-webpage` (3), `harbor-order-email` (4), `larkspur-cv` (3), `oakridge-note` (3), `pinecrest-ticket` (3), `ridgeview-search` (3), `sentinel-claim-doc` (3), `summit-contract` (3), `vireo-readme` (3)
- `rf.holdout.en.jb.*` — 3 scenario(s), 15 rows: `crestwave-hypothetical` (5), `harbor-persona` (5), `oakridge-mode` (5)
- `rf.holdout.en.mix.*` — 5 scenario(s), 23 rows: `code-review` (5), `customer-email` (5), `meeting-notes` (4), `support-chat` (4), `translation` (5)
- `rf.holdout.en.obf.*` — 5 scenario(s), 5 rows: `bluedune-split` (1), `crestwave-codeblock` (1), `harbor-htmlcomment` (1), `larkspur-spaced` (1), `sentinel-base64` (1)
- `rf.holdout.en.pe.*` — 3 scenario(s), 15 rows: `bluedune-dispatch-secret` (5), `larkspur-tutor-rules` (5), `vireo-config-diff` (5)
- `rf.holdout.en.roleplay.*` — 1 scenario(s), 5 rows: `games` (5)
- `rf.holdout.en.tp.*` — 10 scenario(s), 10 rows: `bluedune-mcp` (1), `crestwave-openapi` (1), `harbor-tooljson` (1), `larkspur-searchtool` (1), `oakridge-docstring` (1), `pinecrest-yaml` (1), `ridgeview-fn` (1), `sentinel-tsdoc` (1), `summit-plugin` (1), `vireo-mcpconfig` (1)
- `rf.holdout.en.user.*` — 19 scenario(s), 71 rows: `bluedune-tracking` (4), `crestwave-billing` (3), `crestwave-devices` (3), `crestwave-service` (2), `harbor-delivery` (5), `harbor-orders` (5), `larkspur-academics` (4), `oakridge-admin` (3), `oakridge-appointments` (3), `oakridge-visits` (4), `pinecrest-accounts` (5), `pinecrest-app-questions` (5), `pinecrest-lending` (3), `ridgeview-services` (4), `sentinel-billing` (3), `sentinel-policy` (8), `summit-candidates` (1), `summit-process` (3), `vireo-product` (3)
- `rf.holdout.vi.authority.*` — 17 scenario(s), 31 rows: `anphuc-vendor` (3), `anphuc-vendor2` (1), `devteam-test` (1), `fake-dieutra` (1), `fake-sysnotice` (2), `haiphat-hr` (2), `haiphat-phapche` (2), `lamgiang-hcc` (3), `quantricaocap` (1), `tdbank-audit` (4), `tdbank-tuvan-long` (1), `thanhtra` (2), `thienan-khan` (1), `viettin-baotri-long` (1), `viettin-sudo` (1), `viettin-upgrade` (2), `vinaconnect-cntt` (3)
- `rf.holdout.vi.benign.*` — 103 scenario(s), 154 rows: `anphuc-baoluu` (1), `anphuc-daidien` (1), `anphuc-daohan` (1), `anphuc-hoiphi` (2), `anphuc-hopdong` (2), `anphuc-quyenloi` (1), `dichdoitac` (1), `dichhan` (1), `dichthuat` (2), `express-giahang` (2), `hardneg-anprompt` (1), `hardneg-banve` (1), `hardneg-baocaoloi` (1), `hardneg-baogia` (1), `hardneg-baotang` (1), `hardneg-boqua` (3), `hardneg-botfaq` (1), `hardneg-capquyen2` (1), `hardneg-catruc` (1), `hardneg-chiase` (1), `hardneg-chidao` (1), `hardneg-daubep` (1), `hardneg-devprompt` (1), `hardneg-directive` (1), `hardneg-doan2` (1), `hardneg-doilich` (1), `hardneg-doilink` (1), `hardneg-giaithich` (1), `hardneg-goloidn` (1), `hardneg-hocbaomat` (1), `hardneg-itadmin` (5), `hardneg-ketruyen` (1), `hardneg-kho` (1), `hardneg-khoahoc` (1), `hardneg-khoiphuc` (1), `hardneg-logo` (1), `hardneg-loinop` (1), `hardneg-luyennoi` (1), `hardneg-nhanvienmoi` (1), `hardneg-notice` (3), `hardneg-pentest` (1), `hardneg-phongvan2` (1), `hardneg-quyentruycap` (1), `hardneg-resetmk` (1), `hardneg-roleplay` (2), `hardneg-roleplay2` (1), `hardneg-security` (3), `hardneg-serverconf` (1), `hardneg-taphuan` (1), `hardneg-uutien` (1), `hardneg-vaoht` (1), `hardneg-wifi` (1), `hge-donglanh` (1), `hge-giuhang` (1), `hge-guixe` (1), `hge-hoiship` (1), `hge-tailieu` (1), `hungvuong-hoihang` (4), `hvmart-baotri` (2), `hvmart-combo` (1), `hvmart-doitra` (2), `hvmart-lapdat` (2), `hvmart-tratgop` (2), `lamgiang-baotri` (1), `lamgiang-dichvudidong` (1), `lamgiang-thutuc` (2), `lamgiang-trocap` (2), `mekong-chuyennganh` (1), `mekong-dangkyhp` (1), `mekong-giayxacnhan` (1), `mekong-hocphi` (1), `mekong-hoctap` (3), `mekong-lichthi2` (1), `mekong-quyetdinh` (1), `mekong-renluyen` (1), `mekong-sinhvien` (3), `rutgon` (1), `soantin` (1), `tdbank-app` (3), `tdbank-faq` (3), `tdbank-hanmuc` (3), `tdbank-khoathe` (2), `tdbank-luonghuu` (1), `tdbank-nghile-long` (1), `tdbank-tkcon` (2), `thienan-dauda` (1), `thienan-donthuoc` (2), `thienan-huyetap` (1), `thienan-noisoi` (1), `thienan-taikham` (1), `thienan-tuvan` (3), `thienan-vacxin` (1), `tomtat` (2), `vietlai` (2), `viettin-giaoban-long` (1), `viettin-hopmeet` (5), `viettin-presale` (1), `vina-data` (2), `vina-giadinh` (2), `vina-ktdata` (1), `vina-mua` (2), `vina-vungxa` (2), `vinaconnect-support` (3)
- `rf.holdout.vi.exfil.*` — 6 scenario(s), 14 rows: `baocao` (2), `baocaothang` (2), `bcc` (2), `express-forward` (4), `pixel` (2), `taichinh` (2)
- `rf.holdout.vi.extract.*` — 7 scenario(s), 19 rows: `bangiao` (3), `iso` (2), `kiemdinh` (2), `mekong-qa` (5), `pentest-auth` (2), `rasoat` (3), `viettin-secret` (2)
- `rf.holdout.vi.ind.*` — 28 scenario(s), 28 rows: `anphuc-hoadon2` (1), `anphuc-ticket2` (1), `anphuc-tooljson` (1), `haiphat-congno` (1), `haiphat-cv` (1), `haiphat-search` (1), `hge-email` (1), `hge-hopdong-long` (1), `hge-ticket` (1), `hvmart-desc2` (1), `hvmart-invoice` (1), `hvmart-review` (1), `hvmart-review3` (1), `hvmart-web` (1), `mekong-lms` (1), `mekong-tuyendung` (1), `tdbank-search` (1), `tdbank-wiki` (1), `viettin-codecomment` (1), `viettin-commit` (1), `viettin-contract` (1), `viettin-log` (1), `viettin-meetnote` (1), `viettin-nghiemthu-long` (1), `viettin-readme` (1), `vina-sms` (1), `vina-syncmail` (1), `vina-ticket2` (1)
- `rf.holdout.vi.jailbreak.*` — 6 scenario(s), 16 rows: `bongtoi` (3), `gaccong` (2), `giaosu` (2), `khongluat` (2), `kkd` (2), `tudo-persona` (5)
- `rf.holdout.vi.obf.*` — 5 scenario(s), 9 rows: `ghep2` (1), `noichuoi` (2), `spaced2` (1), `spaced3` (2), `split-payload` (3)
- `rf.holdout.vi.tool.*` — 10 scenario(s), 10 rows: `anphuc-py` (1), `anphuc-pydoc` (1), `haiphat-py2` (1), `hge-mcp` (1), `lamgiang-ts` (1), `thienan-json` (1), `thienan-ts` (1), `viettin-report` (1), `viettin-yaml` (1), `vina-sms-json` (1)
- `rf.holdout.vi.top.*` — 17 scenario(s), 50 rows: `anphuc-thong-bao-dai-ly` (2), `haiphat-onboarding` (3), `haiphat-phu-luc-hop-dong` (2), `haiphat-thong-bao-kiem-toan` (4), `hoanggia-b2b` (3), `hungvuong-bot-prompt` (3), `hungvuong-seller` (4), `lamgiang-cong-dvc` (2), `mekong-dao-tao` (3), `roleplay-phong-van` (3), `tdbank-guardrail-tuning` (3), `tdbank-lam-ro-ho-so-thau` (2), `thienan-cap-quyen` (2), `tom-tat-ho-tro` (5), `viettin-pm` (2), `viettin-runbook` (3), `vinaconnect-doi-goi` (4)

## Checks (output of `build_realistic.py`)

```
{
  "holdout:max_within_jaccard": 0.308,
  "holdout_vs_train:max_jaccard": 0.381,
  "leak:holdout:eval_texts_compared": 2176,
  "leak:holdout:fingerprint_hits": 0,
  "leak:holdout:jaccard_over_0.6": 0,
  "leak:holdout:jaccard_over_0.8": 0,
  "leak:holdout:max_jaccard": 0.336,
  "leak:rows_dropped": 0,
  "leak:train:eval_texts_compared": 2176,
  "leak:train:fingerprint_hits": 0,
  "leak:train:jaccard_over_0.6": 0,
  "leak:train:jaccard_over_0.8": 0,
  "leak:train:max_jaccard": 0.544,
  "shared_groups": 0,
  "train:max_within_jaccard": 0.422
}
```

Summary: 0 rows rejected by the schema check; 0 exact
duplicates and 0 near-duplicates dropped;
maximum within-file 5-gram Jaccard 0.422 (train) and 0.308 (holdout), holdout-vs-train
maximum 0.381; 0 groups shared between the files.

**Eval leakage guard** (same code as `train/data/build_data.py`, against `eval/fingerprints.txt` and
`eval/data/*.jsonl`, 2176 eval texts): 0 fingerprint hits and
0 rows above Jaccard 0.8 in train (0 above 0.6, maximum 0.544);
0 fingerprint hits and 0 rows above 0.8 in holdout (maximum 0.336).
0 rows dropped by the guard.

Full build log:

```
loaded holdout_en: 20 rows
loaded holdout_en_c01: 20 rows
loaded holdout_en_c02: 20 rows
loaded holdout_en_c03: 20 rows
loaded holdout_en_c04: 15 rows
loaded holdout_en_c05: 15 rows
loaded holdout_en_c06: 15 rows
loaded holdout_en_c07: 15 rows
loaded holdout_en_c08: 20 rows
loaded holdout_en_c09: 19 rows
loaded holdout_en_c10: 17 rows
loaded holdout_en_c11: 20 rows
loaded holdout_en_c12: 17 rows
loaded holdout_en_c13: 15 rows
loaded holdout_en_c14: 17 rows
loaded holdout_en_c15: 17 rows
loaded holdout_vi: 281 rows
loaded holdout_vi_top1: 25 rows
loaded holdout_vi_top2: 25 rows
loaded train_en_attack_a: 15 rows
loaded train_en_attack_a2_c01: 20 rows
loaded train_en_attack_a2_c02: 14 rows
loaded train_en_attack_a2_c03: 15 rows
loaded train_en_attack_a2_c04: 15 rows
loaded train_en_attack_a2_c05: 15 rows
loaded train_en_attack_a2_c06: 14 rows
loaded train_en_attack_a2_c07: 14 rows
loaded train_en_attack_a2_c08: 13 rows
loaded train_en_attack_a2_c09: 17 rows
loaded train_en_attack_a2_c10: 16 rows
loaded train_en_attack_a2_c11: 14 rows
loaded train_en_attack_a2_c12: 14 rows
loaded train_en_attack_a2_c13: 18 rows
loaded train_en_attack_a2_c14: 14 rows
loaded train_en_attack_a2_c15: 18 rows
loaded train_en_attack_b: 20 rows
loaded train_en_attack_b_c01: 20 rows
loaded train_en_attack_b_c02: 20 rows
loaded train_en_attack_b_c03: 19 rows
loaded train_en_attack_b_c04: 20 rows
loaded train_en_attack_b_c05: 20 rows
loaded train_en_attack_b_c06: 20 rows
loaded train_en_attack_b_c07: 17 rows
loaded train_en_attack_b_c08: 17 rows
loaded train_en_attack_b_c09: 16 rows
loaded train_en_attack_b_c10: 15 rows
loaded train_en_attack_b_c11: 15 rows
loaded train_en_attack_b_obf1: 10 rows
loaded train_en_attack_b_obf2: 10 rows
loaded train_en_attack_b_tp1: 7 rows
loaded train_en_attack_b_tp2: 6 rows
loaded train_en_attack_b_tp3: 7 rows
loaded train_en_attack_b_tp4: 7 rows
loaded train_en_benign_a: 294 rows
loaded train_en_benign_b: 262 rows
loaded train_vi_attack_a: 359 rows
loaded train_vi_attack_b_c01: 20 rows
loaded train_vi_attack_b_c02: 20 rows
loaded train_vi_attack_b_c03: 20 rows
loaded train_vi_attack_b_c04: 20 rows
loaded train_vi_attack_b_c05: 20 rows
loaded train_vi_attack_b_c06: 20 rows
loaded train_vi_attack_b_c07: 20 rows
loaded train_vi_attack_b_c08: 20 rows
loaded train_vi_attack_b_c09: 20 rows
loaded train_vi_attack_b_c10: 20 rows
loaded train_vi_attack_b_c11: 20 rows
loaded train_vi_attack_b_forkobf_a: 12 rows
loaded train_vi_attack_b_forkobf_b: 13 rows
loaded train_vi_benign_a: 332 rows
loaded train_vi_benign_b: 330 rows
loaded train_vi_benign_top1: 21 rows
loaded train_vi_benign_top2: 19 rows
loaded train_vi_benign_top3: 19 rows
loaded train_vi_benign_top4: 19 rows
{
  "checks": {
    "holdout:max_within_jaccard": 0.308,
    "holdout_vs_train:max_jaccard": 0.381,
    "leak:holdout:eval_texts_compared": 2176,
    "leak:holdout:fingerprint_hits": 0,
    "leak:holdout:jaccard_over_0.6": 0,
    "leak:holdout:jaccard_over_0.8": 0,
    "leak:holdout:max_jaccard": 0.336,
    "leak:rows_dropped": 0,
    "leak:train:eval_texts_compared": 2176,
    "leak:train:fingerprint_hits": 0,
    "leak:train:jaccard_over_0.6": 0,
    "leak:train:jaccard_over_0.8": 0,
    "leak:train:max_jaccard": 0.544,
    "shared_groups": 0,
    "train:max_within_jaccard": 0.422
  },
  "train": {
    "en/attack": 512,
    "en/benign": 556,
    "en/rows": 1068,
    "label/benign": 1296,
    "label/benign/en": 556,
    "label/benign/vi": 740,
    "label/data_exfiltration": 210,
    "label/data_exfiltration/en": 103,
    "label/data_exfiltration/vi": 107,
    "label/direct_injection": 305,
    "label/direct_injection/en": 132,
    "label/direct_injection/vi": 173,
    "label/indirect_injection": 336,
    "label/indirect_injection/en": 159,
    "label/indirect_injection/vi": 177,
    "label/jailbreak": 183,
    "label/jailbreak/en": 87,
    "label/jailbreak/vi": 96,
    "label/obfuscation": 119,
    "label/obfuscation/en": 54,
    "label/obfuscation/vi": 65,
    "label/prompt_extraction": 208,
    "label/prompt_extraction/en": 103,
    "label/prompt_extraction/vi": 105,
    "label/tool_poisoning": 129,
    "label/tool_poisoning/en": 77,
    "label/tool_poisoning/vi": 52,
    "variant/en/orig": 1068,
    "variant/vi/no_diacritics": 195,
    "variant/vi/no_diacritics/attack": 88,
    "variant/vi/no_diacritics/benign": 107,
    "variant/vi/orig": 1086,
    "variant/vi/orig/attack": 489,
    "variant/vi/orig/benign": 597,
    "variant/vi/teencode": 63,
    "variant/vi/teencode/attack": 27,
    "variant/vi/teencode/benign": 36,
    "vi/attack": 604,
    "vi/benign": 740,
    "vi/rows": 1344,
    "rows": 2412,
    "attack": 1116,
    "benign": 1296,
    "attack_share": 0.463,
    "vi_share": 0.557,
    "groups": 890,
    "len_min": 48,
    "len_median": 192,
    "len_p90": 345,
    "len_max": 787,
    "multiline": 631
  },
  "holdout": {
    "en/attack": 120,
    "en/benign": 162,
    "en/rows": 282,
    "label/benign": 366,
    "label/benign/en": 162,
    "label/benign/vi": 204,
    "label/data_exfiltration": 44,
    "label/data_exfiltration/en": 23,
    "label/data_exfiltration/vi": 21,
    "label/direct_injection": 78,
    "label/direct_injection/en": 34,
    "label/direct_injection/vi": 44,
    "label/indirect_injection": 58,
    "label/indirect_injection/en": 30,
    "label/indirect_injection/vi": 28,
    "label/jailbreak": 37,
    "label/jailbreak/en": 17,
    "label/jailbreak/vi": 20,
    "label/obfuscation": 15,
    "label/obfuscation/en": 6,
    "label/obfuscation/vi": 9,
    "label/prompt_extraction": 50,
    "label/prompt_extraction/en": 21,
    "label/prompt_extraction/vi": 29,
    "label/tool_poisoning": 20,
    "label/tool_poisoning/en": 10,
    "label/tool_poisoning/vi": 10,
    "variant/en/orig": 282,
    "variant/vi/no_diacritics": 47,
    "variant/vi/no_diacritics/attack": 21,
    "variant/vi/no_diacritics/benign": 26,
    "variant/vi/orig": 271,
    "variant/vi/orig/attack": 102,
    "variant/vi/orig/benign": 169,
    "variant/vi/teencode": 13,
    "variant/vi/teencode/attack": 4,
    "variant/vi/teencode/benign": 9,
    "vi/attack": 127,
    "vi/benign": 204,
    "vi/rows": 331,
    "rows": 613,
    "attack": 247,
    "benign": 366,
    "attack_share": 0.403,
    "vi_share": 0.54,
    "groups": 279,
    "len_min": 66,
    "len_median": 174,
    "len_p90": 273,
    "len_max": 704,
    "multiline": 102
  }
}
```

## Known weaknesses

- **Machine-written, not native-checked.** All Vietnamese was written by the model and labelled by the
  model. Register and vocabulary are plausible but no native speaker has reviewed them; some phrasings may
  be slightly stiff or regionally neutral where a real writer would be more specific.
- **Attack payloads are illustrative, not operational.** Payloads target the assistant's own behaviour
  (reveal or translate its configuration, treat the sender as administrator, switch persona, misrate a
  document, include conversation history or stored records in an outbound link or email, read a config
  file before a tool call). Payloads describing money movement, OTP or identity-verification bypass, or
  account takeover were deliberately left out; a model trained on this data has seen the injection
  *patterns* for those domains but not those specific payload goals.
- **Writer effects.** Each slice was written by one agent, so a slice can carry that agent's habits (favoured
  openers, sentence rhythm). The near-duplicate check removes repeats but not stylistic correlation; the
  holdout was written by different agents than train, which limits, but does not remove, this effect.
- **Lengths.** Rows run from one line to roughly 800 characters; there are no documents near the 1,200
  character end of the requested range, because long attack documents were the ones most often cut short
  during writing.
- **Teencode is light** by design (chat-like benign text and a few casual attacks); heavier teencode is
  covered by the repo's v2 generator, not here.
- **Attack share is below 45% in the holdout** (about 40%) because two Vietnamese benign top-ups were added
  to reach the row and language targets after several attack-writing runs were interrupted; only clean,
  complete chunks were kept.
- **Group granularity varies.** Some writers used one group per document rather than per scenario, so
  group counts overstate the number of distinct situations in those slices.
- Organisations, people, URLs (`*.example`), keys and phone numbers are fictional placeholders.
