# Fedora VM audit reader validation

This workflow is for the draft audit reader. Run QEMU as a regular host user. It boots verified Fedora Workstation media and a read-only probe ISO with KVM, no guest network, no host filesystem sharing and no persistent guest disk. The probes create isolated fixtures in the guest's volatile overlay. The host's Polkit, audit and SELinux configurations stay intact.

## Run the component probes

Provide QEMU with KVM access, xorriso, gpgv, GNU Coreutils, four virtual CPUs and 6 GiB of available RAM. Download the Fedora Workstation 45 x86_64 Live ISO, its signed checksum file and Fedora's keyring into a local directory. Expected names are `Fedora-Workstation-Live-45-1.4.x86_64.iso`, `Fedora-Workstation-45-1.4-x86_64-CHECKSUM` and `fedora.gpg`. The script checks the Fedora 45 signing fingerprint and verifies the ISO before booting. [Fedora Workstation downloads and verification](https://fedoraproject.org/workstation/download/) · [Fedora signing keys](https://fedoraproject.org/security/)

Run from the draft checkout.

```bash
bash prototype/vm/run.sh baseline "$HOME/Downloads/fedora45"
bash prototype/vm/run.sh gnome "$HOME/Downloads/fedora45"
bash prototype/vm/run.sh sessions "$HOME/Downloads/fedora45"
```

Each run prints its temporary directory and the relevant lines from `guest.log`. The baseline checks enforcing mode, real bus credentials for a non-root caller, logind and Polkit rejection of a sessionless caller, the guest `ausearch` executable with a synthetic file, and removal of the temporary action. The GNOME probe runs as the ephemeral desktop user and compares real logind session lookup with Polkit's decision. It requests cancellation if the interactive check remains pending. The synthetic records are written outside the system audit log. The probes run without starting the reader. [QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html)

The sessions probe opens real guest logins through standard getty and PAM, with two local consoles and one fixture login marked remote via PAM. An SSH transport is outside this probe's scope. It runs the prototype's binding check against the guest system bus and uses `pkttyagent` to test the draft action directly. Separate disposable guest accounts provide the requesting identity and an administrator credential generated for the test. The test publishes only decision status and discards the credentials with the guest.

## Observed on Fedora Workstation 45 in KVM

- The Live image booted with SELinux Enforcing. The guest system bus supplied UID, PID and a live process descriptor for a non-root caller.
- Logind returned `NoSessionForPID` for the sessionless caller. Real Polkit returned unauthorized without a challenge for the draft action.
- Guest `ausearch` returned the synthetic permissive AVC and its related PATH record. This check exercised the fixture independently of authorization.
- GNOME autostart ran under `user@1000.service` in two runs, once in the GNOME session manager service and once in a transient application scope. Logind showed a distinct active, local Wayland login on `seat0` in `session-1.scope`. `GetSessionByPID` returned `NoSessionForPID` for the probe and `sd_pidfd_get_session` returned `ENODATA`. The probe's kernel audit session was 2, while the graphical login reported audit session 1.
- Polkit's noninteractive result for the GNOME probe was unauthorized with a challenge. The interactive request returned rejection before cancellation could be sent. The probe did not establish the reason for that rejection.
- The baseline confirmed removal of the temporary action from the guest filesystem. Packaged-service removal remains untested.
- Two local console logins under the same UID had distinct scopes on seat0. Logind marked only the foreground login active, while Polkit offered a challenge to both. The draft bound only the active local session. Switching from one console to the other reversed the binding, and terminating the inactive login removed its bus connection.
- The PAM-marked remote login shared the console users' UID. Real logind set `Remote=true` and the binding check refused it both in the background and while its VT was foreground and logind reported `Active=true`. Polkit offered a challenge in both states.
- The active console's real Polkit text agent accepted the disposable administrator's credentials without a temporary grant. The next noninteractive check required a fresh challenge. Cancelling an in-flight prompt and interrupting another both returned denial. A requester connection closed during a prompt lost its bus name, an authorization wait timed out and was cancelled, and the real authority rejected a malformed Polkit method signature. The console checks exercised the actual authority independently of a reader invocation.

This was Fedora Workstation Live 45-1.4 x86_64 under QEMU 11.1.3 with KVM, GNOME Shell 51.0-1.fc45, systemd 262-3.fc45, Polkit 127-5.fc45 and dbus-broker 37-9.fc45. The prototype treats an unresolvable session as ineligible. The GNOME result blocks desktop integration until a trusted, connection-bound active local session association is demonstrated. [Caller identity findings and decision](AUDIT_ACCESS.md#caller-identity-findings-and-decision)

The component probes did not start the audit service. Private-bus tests use the real D-Bus transport with simulated authorization and logind transitions to exercise malformed reader requests, rate limiting, disconnect cleanup, discard on session switch during collection, and refusal of temporary grants. End-to-end cancellation and cleanup on a deployed system-bus service remain unverified.

## Integration matrix for the candidate service

Create a fresh disposable installed Fedora GNOME VM from the verified ISO and a scratch qcow2 disk. Remove the media after setup and snapshot the clean guest. Use a regular desktop account and a separate guest administrator for authentication. For remote-session cases, use a private virtual network with a second disposable guest. Keep the guest enforcing and perform all setup and requests in the VM.

A candidate must specify a dedicated service identity, limited system-bus policy, executable and activation unit, bounded CPU and memory, a confined SELinux domain, and narrow read-only access to the intended audit files. Record OS and package versions, tested commit, enforcing mode, service UID and context, unit limits, and expected and actual outcomes. Use synthetic fixtures and status summaries in published results.

| Case | Required observation |
| --- | --- |
| Explicit system-bus request from the GNOME launcher path | A live peer resolves to its active local session. Administrator authentication is required. Successful authorization replies only to the requesting connection. Startup and refresh stay unprivileged. |
| Missing interaction flag, wrong method signature, inactive, remote and sessionless callers | Zero prompts, audit opens and returned records. Exercise remote and local activity under the same UID. |
| Denied and dismissed prompts, disconnect, and session switch during lookup or collection | Zero returned records. Authentication and audit child are cleaned up and the request slot is released. |
| Read-only identity and confinement | Verify the actual UID, SELinux domain, configuration and log paths. Demonstrate denial of writes and out-of-scope access with enforcing policy intact. |
| Authorized collection using synthetic audit data | Supply a VM-only fixture as the configured source inside the candidate's test namespace. The authentic D-Bus and Polkit path returns the expected audit identity, AVC fields and permissive flag within the wire limit. A second caller receives no unsolicited records. |
| Timeout, oversized output and malformed results | Exercise the actual reader and service limits. Confirm distinct failure statuses, no raw diagnostic disclosure and no remaining collector process. |
| Removal and repeat boot | Compare account, file permission, D-Bus, Polkit and systemd state to the clean snapshot. Verify the service and its grants are absent and SELinux remains enforcing. |

Authenticated collection, active/inactive and remote session handling, in-flight cancellation, confinement, end-to-end limits and package removal remain integration gates. Keep the reader draft until these results are reviewed and documented.
