# Host With the Most - Luna handoff (Day 02)

Driver (Claude CLI) has fully cracked the method. Luna: read the Game Master `start` task
text for THIS attempt, decode the assigned file with the solver below, read off the exact
scored property, and submit. **Never hard-code a value** - Time Trial / Mastery assign a
different file each attempt.

## 1. Unlock the archive
- The zip is AES-256. **Password: `infected`** (standard malware-zip convention; verified).
- `7z x -pinfected host_with_the_most.zip -oextracted`

## 2. Decode every fixture (deterministic, safe)
- Copy `scripts/solve_host.js` into the VM, then:
  `node solve_host.js extracted`
- It sandboxes `ActiveXObject`/`WScript` (throws), so the dropper sinks (`huntress_lab_*`,
  `shell.Run`, `FileSystemObject`) can never run. It only calls each file's pure `inspect_*`
  entry and base64-decodes the `.ps1` `FromBase64String()` literal. Output = one JSON line
  per fixture (`stageCount`, `steps`, `adapter`, `campaign_id`, full `values`) plus a
  "candidate answers" block.
- If the VM has no Node but has Python, the obfuscation families are: per-file single-byte XOR,
  XOR-with-5-byte-key, array-reverse, reverse+XOR, base64, `:`-hex, `-`-decimal, and `%xx`
  URL-encode - each wraps a JSON config `{steps, adapter, values{campaign_id,...}, stageCount}`.

## 3. Answer the EXACT GM question
The decoded content carries NO embedded `flag{}` / answer token (confirmed) - this is a
derived-answer triage task, so the GM `start` text names the property. Likely phrasings and
where to read the answer from the solver output:
- "host/stage with the **most** stages" -> the fixture with max `stageCount` (its `campaign_id`,
  filename, or `adapter` - match the wording).
- "most-used host object/adapter" -> highest-count entry in `adapter frequency`.
- a specific field of a named stage -> read it straight from that file's `values`.

In this prep copy, max `stageCount` = 4 is a TIE (`relay-handoff.js` campaign-169b97ec9a /
WinHttp.WinHttpRequest.5.1 **and** `staged-handoff.js` campaign-b2e9046e6f / Microsoft.XMLHTTP).
A real per-attempt file will almost certainly have a unique leader - trust the solver's output
for the assigned bytes, not these prep values.

## 4. Submit + verify
- Submit the computed value under the GM `answer_id` for Host With the Most (Single Solve ->
  Time Trial -> Mastery). Report each accepted result + the returned completion hash back to the
  driver, then verify points in CourseStack.

## Reference: prep-copy stage map (example.invalid placeholders)
| file | stageCount | adapter | campaign_id |
|---|---|---|---|
| staged-handoff.js | 4 | Microsoft.XMLHTTP | campaign-b2e9046e6f |
| relay-handoff.js | 4 | WinHttp.WinHttpRequest.5.1 | campaign-169b97ec9a |
| outbound-transfer.js | 3 | CertReq.exe | campaign-30b8616db1 |
| impact-plan.js | 3 | ADODB.Stream | campaign-ee4a70e428 |
| remote-write.js | 2 | MSXML2.XMLHTTP.6.0 | campaign-99e39528bf |
| memory-stage.js | 2 | MSXML2.XMLHTTP.6.0 | campaign-a3a04f5ced |
| embedded-write.js | 2 | ADODB.Stream | campaign-e0aa64e87e |
| local-dispatch.js | 2 | regsvr32.exe | campaign-3f8e0c467a |
| host-context.js | 2 | Scripting.Dictionary | campaign-e8c441b095 |
| resource-sample.ps1 | - | (Resource Dev: wallet/Run-key) | a=1c94fc0eeae4 |
| collection-sample.ps1 | - | (Collection: Login Data/Cookies -> zip) | a=a593e561fb02 |
| impact-sample.ps1 | - | (Impact: .locked ext + RECOVERY note) | a=bd68883e3dd4 |
