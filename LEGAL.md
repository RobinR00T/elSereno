# Legal and acceptable use

ElSereno is a tool for authorised security work. Reading this document is
mandatory before the first run; the binary refuses to operate until an
explicit acknowledgement is recorded.

## Acceptable Use Policy (AUP)

You may use ElSereno only:

1. Against systems **you own**, or
2. Against systems for which you have **documented, current, written
   authorisation** from the system owner, and
3. Within the scope, time window, and target list defined in that
   authorisation.

You must **not** use ElSereno to:

- Scan, fingerprint, or interact with systems you do not own and are not
  explicitly authorised to test.
- Perform write operations, exploitation, credential harvesting, or
  out-of-band dialing outside your authorisation scope.
- Disrupt availability, induce denial of service, or degrade safety
  functions of industrial control systems.
- Dial emergency or premium-rate numbers. ElSereno hard-blocks ≤3-digit
  numbers; operators are responsible for additional jurisdictional
  blacklists via `scope.yaml`.

## Legal framework (non-exhaustive)

Operators remain responsible for compliance with all applicable laws. The
following are illustrative and not legal advice:

- **Spain / EU**: Ley Orgánica 10/1995, art. 197 bis (acceso ilícito a
  sistemas informáticos); Convention on Cybercrime (Budapest 2001);
  NIS2 Directive (EU) 2022/2555; GDPR (EU) 2016/679.
- **United States**: Computer Fraud and Abuse Act (18 U.S.C. § 1030);
  Electronic Communications Privacy Act; state-level unauthorised-access
  statutes.
- **Industry-specific**: IEC 62443 (industrial communication networks),
  NERC CIP (bulk electric systems), safety-of-life considerations for
  transport, lifts (EN 81-28), process control, and medical systems.

When in doubt, do not scan. Obtain authorisation first.

## GDPR considerations

ElSereno may incidentally collect data that qualifies as personal data under
GDPR:

- **IP addresses** of scanned targets.
- **Banners** that disclose operator or site identifiers.
- **IMSI / IMEI** captured via AT-modem interrogation.
- **Phonebook entries** harvested from modems.

The **operator is the data controller** for any such processing. ElSereno
supports responsible handling:

- **Minimisation**: evidence truncation at `evidence.max_payload_bytes`
  (default 16 KiB); only hashes of full bodies are retained when truncated.
- **Retention**: configurable per-class via `retention.{findings_days,
  evidence_days, runs_days}` with a keep-if-referenced rule for evidence.
- **Anonymisation**: reports can redact addresses and identifiers.
- **Encryption at rest**: IMSI / IMEI / phonebooks are written only to the
  encrypted vault (AES-GCM + Argon2id); never to plain log or finding
  payloads.

## Acceptable-use acknowledgement flow

1. On first launch, ElSereno prints this document and requires the operator
   to type `I AGREE` verbatim.
2. The acknowledgement is stored in `~/.elsereno/ack.v1` with a checksum of
   the disclaimer text.
3. If the disclaimer text changes (checksum mismatch), re-acknowledgement is
   required.
4. `elsereno legal show` re-prints the disclaimer at any time.
5. If `scope.yaml` is absent, active commands display an additional banner
   prompting the operator to create one.
6. Offensive builds (`-tags offensive`) with `--dial-allowed` display an
   additional warning about telephony cost and traceability.

## Disclaimer of warranty

ElSereno is provided under the MIT License "AS IS", without warranty of any
kind. The authors and copyright holders are not liable for any claim,
damages, or other liability arising from the use of the software. See
`LICENSE` for the full text.
