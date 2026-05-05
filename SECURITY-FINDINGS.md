# Vryionics VR Optimization Suite — Security Findings

*Drafted by Claude (Anthropic), reviewed and edited by darkswordsman. Findings went through an internal second-opinion pass using the `security-review` skill and a separate peer-review pass that corrected over-collapsed severity tiers and missed exploit paths in earlier drafts; remaining errors are mine.*

Scope: Electron main, preload, and renderer code. Did not audit the rules/data tables. Paths are relative to the `Vryionics-VR-Optimization-Suite` repo root.

This document went through four passes: an initial broad scan, a self-pruning pass that removed perf/reliability nits, an independent second-opinion review using the `security-review` skill's strict false-positive filter, and a peer-review revision that re-tiered several items the strict filter had over-collapsed. The doc is organized as:

- **Section 1: Real vulnerabilities** — issues a security engineer would confidently raise as exploitable defects.
- **Section 2: Hardening items** — defense-in-depth gaps and latent unsafe contracts. Two tiers within: Medium-tier items are admin-privileged sinks one careless caller away from RCE; Low-tier items are pure hygiene with no concrete exploit path.

## Severity rubric

- 🟣 **Critical** — direct code execution / privilege escalation reachable today by an unprivileged attacker without needing an additional bug.
- 🔴 **High** — code execution / privilege escalation reachable with one realistic preceding condition.
- 🟡 **Medium** — exploitable only with significant additional access, OR a defense-in-depth gap that materially weakens the system.
- 🟢 **Low** — hardening issue with no realistic exploit path today.

## Operating context: the app runs elevated

VROS is designed to run as administrator. HKLM registry writes, `Stop-Service` / `Start-Service` on Windows services, `Checkpoint-Computer`, NSIS driver installers, and `NtSetSystemInformation` for the standby-list flush all require admin. `system:isAdmin` (`ipc/system.ts:14`) probes for elevation and several fixes set `requiresAdmin: true` explicitly.

This raises the consequence ceiling of every shell-injection-class finding to "SYSTEM-equivalent on the user's machine." The auto-updater finding below is the worst case because the silent-install path runs at admin without any further UAC prompt.

A relevant Electron baseline: `index.ts:62-63, 92-93` set `contextIsolation: true` and `nodeIntegration: false`. With contextIsolation on and no remote content loaded, a renderer XSS would not get direct Node access — but the IPC bridge is still reachable, which is what the Section 2 findings address.

**Admin-related operational issues** users have reported and which this audit confirms (operational, not vulnerabilities):

- **Orphan admin PowerShell after crashes.** `lockTimerResolution` (`optimizer.ts:593-615`) spawns a detached PS that sleeps 24 h holding the system timer at 0.5 ms. If VROS crashes between lock and unlock, that PS process keeps running and VROS can't recover its PID on next launch. Users see a stray admin `powershell.exe` in Task Manager.
- **Services left stopped after a crash.** Comments in `index.ts:182-184` and the explicit `recoverStoppedServices()` call on launch confirm this is a known failure mode for the live optimizer's service-stop path. Audio / Search / Spooler can be left stopped if the app dies mid-session. Stopping these services is also a common malware-staging behavior, which contributes to AV/EDR false-positive alerts on VROS — together with the `-ExecutionPolicy Bypass` flag on every PS spawn (the specific flag profile that AV heuristics flag as living-off-the-land).

---

# Section 1: Real vulnerabilities

## 1. Auto-updater verification path — `src/main/updater.ts` + `electron-builder.yml`

🔴 **[High]** Conditional SHA-512 verification + no Authenticode check + `verifyUpdateCodeSignature: false`.

**The literal conditional** (`updater.ts:231-242`):

```ts
if (this.latestReleaseSha512) {
  const fileBuffer = fs.readFileSync(dest)
  const fileHash = crypto.createHash('sha512').update(fileBuffer).digest('base64')
  if (fileHash !== this.latestReleaseSha512) {
    console.error('[Updater] SECURITY: Installer hash mismatch!')
    fs.unlinkSync(dest)
    throw new Error('Installer hash verification failed — possible tampering')
  }
  console.log('[Updater] SHA-512 hash verified OK')
} else {
  console.warn('[Updater] No SHA-512 available — skipping verification')
}
```

`this.latestReleaseSha512` is populated upstream from `latest.yml` (`updater.ts:150-162`). It stays null in three cases, all of which fall through to the `else` branch and install the unverified .exe:

1. The release has no `latest.yml` asset at all (`ymlAsset` is undefined; the entire SHA-fetch block at line 151 is skipped).
2. `fetchAssetText` for `latest.yml` throws — caught locally, only a warning is logged.
3. `latest.yml` is fetched fine but the regex `sha512:\s*(.+)` doesn't match.

**No fallback verification exists.** The file's own header comment (`updater.ts:5-11`) states: "No electron-updater dependency — pure GitHub API + NSIS + PowerShell." So the SHA-512 check is the *only* verification of the downloaded .exe; there's no Authenticode check (the driver installer at `installer.ts:246-280` has one; this auto-updater does not), and `electron-builder.yml:18` has `verifyUpdateCodeSignature: false` with no installer signing.

**Polling cadence:** `updater.ts:101` defines `startBackgroundPolling(intervalMs = 120_000)` — every install in the wild auto-checks every 2 minutes after a 5-second initial delay (`index.ts:248-253`).

**Attack path:** an attacker with control over a GitHub release (compromised repo / leaked publish PAT / hostile fork takeover) publishes `Vryionics-VR-Optimization-Suite-Setup-X.Y.Z.exe` without a `latest.yml`. Within 2 minutes every install downloads it and runs it silently at admin, bypassing the SmartScreen prompt that would normally fire on first-run of an unsigned installer. Result: SYSTEM-equivalent RCE on every install.

**Realism:** the pre-condition (release-pipeline compromise) is non-trivial but is the primary documented threat model for software-update systems. The independent second-opinion review tagged this at confidence 7 on its 1–10 scale[^1] — the only finding in the audit that survives strict false-positive filtering as a defect worth a security-team callout.

**Fix:** make SHA-512 mandatory (refuse to install if `latest.yml` is missing or sha512 line absent). Add Authenticode signature verification on the downloaded .exe matching the existing driver-installer pattern in `installer.ts:246-280`. Sign the installer; flip `verifyUpdateCodeSignature: true`.

[^1]: The `security-review` skill's confidence rubric: 7–10 is "high-confidence real vulnerability," with ≥8 the threshold for "would survive a strict PR-review filter." This finding lands at 7 because the realistic exploit requires GitHub-side compromise that would defeat SHA verification just as effectively in many scenarios; it is still the right thing to fix and is materially less safe than mainstream auto-update implementations.

## 2. Storage debloat JSON → PowerShell at admin — `src/main/scanner/modules/storage-debloat.ts`

🔴 **[High]** `storage-categories.json` interpolated into PS double-quoted strings, loaded from a per-user-writable install directory.

**The problem:** `storage-debloat.ts:102-117` and `:296-379` build PowerShell scripts by interpolating `pathExprs` and `fileFilter` strings from `storage-categories.json` directly into PS double-quoted literals. Double-quoted PS evaluates `$(...)` subexpressions, so a path expression of `"$(<arbitrary PS>)"` executes the inner expression at scan time.

**Why this is a privilege-escalation primitive.** I previously dismissed this as "you already lost if you can write to the install dir," but `electron-builder.yml:30` sets:

```yaml
nsis:
  perMachine: false
```

Per-user NSIS installs land in `%LOCALAPPDATA%\Programs\<product>\`, which is writable by the unprivileged user. The JSON file is loaded from `process.resourcesPath` (`storage-debloat.ts:60`), which resolves to the install dir's `resources/` folder.

**Attack path:**

1. User-level (non-admin) attacker writes a crafted `storage-categories.json` into `%LOCALAPPDATA%\Programs\Vryionics-VR-Optimization-Suite\resources\storage-categories.json`.
2. Next time the user runs VROS as administrator (which is the intended operating mode) and triggers a Storage Debloat scan, the PS interpolates the attacker's `$(...)` payload into a script and executes it at admin.
3. Result: user-level → admin privilege escalation. UAC bypass primitive.

**Realism:** higher than the auto-updater finding for any system that already has user-level malware. User-level malware routinely persists by writing to `%LOCALAPPDATA%`; this gives any such malware a clean escalation path the first time the user runs a Storage Debloat scan.

**Fix:** stop interpolating JSON values into PS source. Either (a) parameterize properly via `$args` / `param()` blocks so values are typed as data not code, (b) use single-quoted PS with explicit `'` escaping, or (c) move the path resolution into the TypeScript layer and pass already-resolved absolute paths to PS.

---

# Section 2: Hardening items

## Section 2a: Medium-tier — latent admin shell sinks

These are functions whose signatures accept arbitrary strings and pipe them to `cmd /c` or PowerShell at admin. Today every caller passes hardcoded constants, so they aren't exploitable. They sit at Medium because they fit the rubric's "defense-in-depth gap that materially weakens the system" tier: one careless refactor lands user input in any of these and you have RCE at admin. They deserve a tier above pure hygiene because the cost of getting them wrong is high.

- 🟡 **[Medium]** `src/main/utils/powershell.ts:64-80` — `runCmd(command)` → `cmd /c <command>` re-parses metacharacters (`&`, `|`, `>`, `^`, `%var%`). Should accept `(cmd, args[])` like the PS variant.
- 🟡 **[Medium]** `src/main/fixes/engine.ts:2570-2589` — `createRestorePointIfDue(reason)` via `execAsync` + cmd shell, only `'`-stripping. `reason` is currently `fix.name` (hardcoded), but the function takes an arbitrary string.
- 🟡 **[Medium]** `src/main/live-optimizer/optimizer.ts:324-358` — `stopService(name)` / `startService(name)` interpolate `name` into single-quoted PS with no `'` escape. `name` currently only comes from the hardcoded `SERVICES_TO_STOP_DURING_VR` array.
- 🟡 **[Medium]** `src/main/ipc/system.ts:59-62` — `app:openExternal` accepts any URL with no scheme check. With `contextIsolation: true` and no XSS sink in the renderer today, there is no untrusted-input attack path. But this is the textbook Electron "defense-in-depth gap that materially weakens the system" finding — the project is one renderer XSS away from arbitrary protocol-handler invocation (`file://`, `ms-cxh-full:`, `search-ms:`, SMB UNC). An `https:`-only allowlist is a one-line fix and makes the system resilient to a class of future bugs.
- 🟡 **[Medium]** `src/main/index.ts:109-112` — `setWindowOpenHandler` calls `shell.openExternal(details.url)` with the same lack of scheme allowlist. Same class as above.

## Section 2b: Low-tier — hygiene with no concrete exploit path

- 🟢 **[Low]** `src/main/index.ts:59-65, 89-94` — `sandbox: false` on both windows. With `contextIsolation: true` and no XSS sink in the renderer, no concrete attack path. Setting `sandbox: true` is best-practice and would protect against any future XSS.
- 🟢 **[Low]** `src/preload/index.ts:256-260` — generic `on(channel, callback)` with no allowlist. Channels available to subscribe carry status data, not secrets (the GitHub token never crosses IPC).
- 🟢 **[Low]** `src/main/ipc/system.ts:53-56` — `config:set` accepts arbitrary `(key, value)` from renderer. Renderer can stomp `vros-config` keys but no path to code execution.
- 🟢 **[Low]** `src/main/utils/powershell.ts:16-42` — predictable temp filename + `-ExecutionPolicy Bypass`. Per-user `%TEMP%` ACL on Windows blocks the TOCTOU substitution scenario in default configurations. `-ExecutionPolicy Bypass` is not a security boundary (any local user can set it); see also the operating-context note above about its AV-heuristic implications.
- 🟢 **[Low]** `src/main/updater.ts:30-48` — `getGithubToken()` loader still exists. No token is shipped today (`electron-builder.yml` confirms). Worth deleting the loader code defensively.
- 🟢 **[Low]** `src/main/updater.ts:307-418` — template-literal PS script newline injection. All interpolated paths come from Electron-controlled APIs; the "newline-in-NTFS-path" scenario requires prior admin write to the user profile.
- 🟢 **[Low]** `src/main/drivers/installer.ts:182-230` — `downloadFile` no host allowlist on redirects. Authenticode + SHA-256 checks downstream gate the install. The hypothetical chain (overly-broad `TRUSTED_PUBLISHERS` entry + redirect-controlled signed-but-different binary) requires a separate curation bug.
- 🟢 **[Low]** `src/main/live-optimizer/optimizer.ts:445-470, 502-532, 546-563, 687-689` — inline `-Command` with embedded process names + only `"` escaping. Process names come from `Get-Process`. Exploiting the `'`-escape gap requires already running a hostile-named process on the box (= prior code execution).
- 🟢 **[Low]** `src/main/ipc/live-optimizer.ts:77-81` — `liveopt:setConfig` writes unvalidated renderer payload. DoS-class only; strings in the config don't reach shell commands.
- 🟢 **[Low]** Pervasive `payload as Type` IPC casts without runtime validation (`liveopt:setConfig`, `config:set`, `setup:saveSetup`, `profile:applyImported`, `support:sendBugReport`, `storage:deleteCategories`). No proven security impact at any sink today. Schema validation (zod / valibot / hand-rolled guards) is good hygiene.
- 🟢 **[Low]** Inline `-Command` PowerShell is widespread despite `powershell.ts:5` forbidding it. Each instance triaged individually; the high-impact ones are in Section 2a.
- 🟢 **[Low]** No CSP set in the renderer. With no remote content loaded, no concrete exploit path.
- 🟢 **[Low]** No `app.on('web-contents-created', …)` hardening. Overlay window has no `setWindowOpenHandler` lockdown — but it loads only local content.

---

# Triage summary

1. **Fix now (real vulnerabilities):**
   - 🔴 **[High]** Auto-updater verification chain — mandatory SHA-512, Authenticode verification, sign the installer, set `verifyUpdateCodeSignature: true`.
   - 🔴 **[High]** Storage debloat JSON-PS injection — stop interpolating JSON values into PS source; parameterize as data.

2. **Pre-emptive hardening of admin-privileged sinks (Medium, cheap):**
   - Scheme allowlist (`https:` only) on `app:openExternal` and `setWindowOpenHandler`.
   - Make `runCmd` accept `(cmd, args[])` or remove it entirely.
   - Migrate `createRestorePointIfDue` and `stopService` / `startService` to the temp-`.ps1` helper or to typed parameters.

3. **General hygiene milestone (Low):**
   - `sandbox: true` on both windows. Add CSP. Lock down `web-contents-created`. Channel allowlist on the preload `on:` helper. Schema-validate IPC entries. Migrate remaining inline `-Command` to temp-`.ps1`. Drop `-ExecutionPolicy Bypass`. Delete the dead `getGithubToken()` loader.

4. **Operational (not security):**
   - Persist the `lockTimerResolution` PID across launches so VROS can clean up its own orphan PowerShell processes on next start.
   - The uniform temp-`.ps1` migration above also reduces the AV-heuristic false-positive surface.
