# Authorized-use boundary

**Status:** Normative. This document defines the only permitted use of the
`maria-padilha-de-castela` image and of the tools included in it.

## 1. The boundary

Use this image **only** on:

- owned systems you control; or
- systems for which you hold **explicit, written permission** to test.

Permission must identify, at minimum:

- the person or organization granting it;
- the exact systems, addresses, accounts, and services in scope;
- the permitted methods and any excluded methods;
- the start and end time of the test;
- an emergency contact and a stop procedure; and
- how any captured data will be handled, retained, and destroyed.

If any of those points is missing or ambiguous, the target is out of scope. A
general statement such as "we are a security company" or "this is a lab" is not
authorization for a specific third-party system.

**Third-party systems are out of scope.** This includes internet-wide scanning,
shared hosting, cloud accounts you do not own, employer systems without written
permission, and "bug bounty" targets whose program rules do not expressly cover
the activity. A public bug-bounty page is not a substitute for checking its
scope and rules.

This image is not for anonymity, evasion, unauthorized access, or "testing"
someone else to prove a point.

## 2. Explicit banner

The authorized-use banner is part of the build, not optional documentation. The
reference build displays a banner before login (`/etc/issue`) and after login
(`/etc/motd`). The text must contain the following meaning, in plain language:

> **AUTHORIZED USE ONLY.** Use this image only on systems you own or have
> explicit written permission to test. Unauthorized access, scanning of
> third-party systems, phishing, and credential theft are prohibited and may be
> illegal. No scans run by default. Define an explicit target scope before
> running any tool, and stop and clear the scope when finished.

The Calamares welcome screen and any future first-run flow must show the same
boundary. The banner must not be dismissible as a one-time click-through that
silently enables scanning. It is a visible reminder of the boundary, not a
substitute for authorization.

The installer's optional security tool groups are not selected by default. They
only install packages; they do not start a scanner, capture, service, or target
discovery. See [`security-tool-groups.md`](security-tool-groups.md) for the
group definitions, the mandatory core, and the redistribution review.

## 3. Defaults

The following are prohibited in the image and in any future panel:

- **No default scans.** No network discovery, port scan, host enumeration, or
  service fingerprinting starts at boot, login, installer completion, or first
  launch. No systemd service, timer, cron job, shell profile, desktop autostart
  entry, or Calamares post-install hook invokes a scanner.
- **No automatic target discovery.** The image must not populate a target list
  from the local network, captured traffic, or an external service.
- **No bundled phishing templates.** No email templates, landing pages, SMS or
  messaging pretexts, credential-capture forms, or cloneable login pages are
  shipped. Tools that include such material must have it removed or disabled
  before packaging, and the removal must be tested.
- **No credential theft.** No credential dumping, browser or keychain
  extraction, keylogging, token theft, fake authentication portals, or
  man-in-the-middle credential capture. Tools whose primary purpose is obtaining
  another person's credentials are not admitted.
- **No stealth or persistence features enabled by default.** No hidden
  exfiltration, beaconing, backdoor installation, or log tampering.
- **No destructive default action.** Destructive modules require an explicit
  action and a confirmation that names the target; they are not part of the
  initial reference build.

## 4. Positive controls

### Target scope

Before a tool can act, the operator must enter or select a target scope. The
scope must be visible while the tool is running. A **Stop** action must cancel
the current operation, and a **Clear** action must remove the scope and any
queued targets. The scope indicator is a safety control, not a claim that the
tool is authorized: the operator remains responsible for the written
authorization.

The private cyber frontend in [`frontend/cyber/`](../../frontend/cyber/README.md)
implements this boundary. Its dedicated tab registry exposes Nmap, SET,
Wireshark/forensics, and a lab/VM launcher only when the private build and the
`MARIA_PADILHA_CYBER_FRONTEND` flag are both enabled. Every offensive panel
renders the authorization banner, lab-mode state, target-scope indicator, and
Stop/Clear actions. Lab mode requires an acknowledged written-authorization
reference, and the runner refuses to start without a bounded scope. A missing
tool produces a fallback and no command is run. SET remains registered for
transparency but is policy-blocked and has no launch control. No scanner,
capture, VM, or service starts automatically.

### Tool admission

Every package is admitted by a reviewed allowlist. A tool is eligible only if:

1. its primary purpose is consistent with authorized lab work (assessment,
   analysis, forensics, or isolated virtualization);
2. it can be used without bundling phishing templates or credential-theft
   payloads;
3. its license permits redistribution in the private image, or the image omits
   it;
4. its export classification has been reviewed; and
5. its default configuration is non-scanning and non-destructive.

A dual-use tool is not automatically admitted. The review must explain why the
tool is needed, what its defaults are, and how misuse is constrained. A denylist
of known credential-theft and phishing packages is maintained alongside the
allowlist, but the allowlist is the primary control.

The initial reference build deliberately excludes SET and any phishing kit.
Adding a tool that can generate phishing content requires a new policy review,
removal of bundled templates, and a test proving the templates are absent.

### Data handling

Capture only what the authorized test needs. Store captures encrypted, restrict
access, define a retention period, and delete them when the engagement ends.
Do not exfiltrate third-party data. If you encounter data that is outside the
scope, stop, preserve it only as required by the engagement, and notify the
authorizing contact.

## 5. Prohibited conduct

The following are never permitted with this image:

- accessing, modifying, or disrupting a system without authorization;
- scanning or enumerating third-party networks or the public internet;
- phishing, social-engineering campaigns, or credential harvesting;
- stealing, dumping, cracking, or replaying another person's credentials;
- deploying malware, ransomware, rootkits, backdoors, or command-and-control;
- establishing persistence on a system you do not own;
- denial-of-service or destructive testing outside a specifically authorized
  and controlled lab;
- evading detection, logging, or law-enforcement attribution;
- violating privacy, data-protection, or export-control law; or
- helping another person do any of the above.

## 6. Enforcement and response

- `tests/all.sh` checks that the reference build contains the banner, does not
  ship default scanner units, and does not ship phishing-template assets.
- Package additions are reviewed against this document before they enter the
  manifest.
- A build that fails the policy checks is not signed or released.
- If a shipped tool or template is found to violate this boundary, remove it,
  rebuild, and document the correction.
- Suspected misuse is outside the project's control, but the project will not
  provide support, templates, or configuration intended to enable it.

## 7. No warranty and no permission

The image is provided as-is for authorized lab use, without warranty. This
document does not grant permission to access any system. Only the system owner
or an authorized representative can grant that permission, in writing, for a
specific scope and time.
