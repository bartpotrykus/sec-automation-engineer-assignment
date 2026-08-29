# Executive Summary — VulnTracker Security Review

## The bottom line

VulnTracker holds one of the most sensitive inventories a security team owns: the list of the
weaknesses we already know about but have not yet fixed, and who is responsible for each. In the
condition we received it, that inventory was effectively unlocked. A person who could see the
application's code — an insider, a contractor, or anyone who obtained a copy — could impersonate any
user, read every finding across all teams, and even retrieve stored login data. In plain terms, the
system that maps where the company is exposed was itself one of the easiest things to break into. After
this work, the direct paths to that outcome are closed, and the build now automatically blocks new
critical flaws from shipping. Meaningful risk remains in areas we consciously deferred, described below.

## Posture: before vs. after

**Before — High/Critical exposure.** Identity could be forged directly from the code; the search
feature could be tricked into handing over the entire database, including password data; any logged-in
user could read other teams' findings; error pages leaked internal system details; and passwords and
keys were written in plain text inside the code and its history.

**After — Moderate, mostly deferred residual risk.** Identity can no longer be forged, the database can
no longer be tricked into surrendering data, users see only their own records, error messages no longer
reveal internals, passwords are never logged, and the shared-report feature we added resists guessing
and link tampering. Every code change is now checked by automated security gates in the build pipeline
that stop critical issues before they merge.

## Top 3 residual risks (and why they remain)

1. **Previously exposed secrets are still compromised until rotated.** We removed the embedded keys and
   passwords from the code, but the old values already existed in the project's history and must be
   assumed known. Until they are rotated and the history is cleaned, someone who saw them earlier could
   still use them. *Why not done here:* rotation is an operations action (new keys in the secrets vault,
   history purge), not a code change.

2. **The notification service can still be abused.** It accepts webhook registrations without
   authentication and can be induced to make requests to internal systems while leaking an internal
   key. *Why not done here:* the brief scoped this engagement to the main application; the service was
   left unchanged and documented. It is currently constrained by network isolation, not by design.

3. **The application is a prototype, not production-hardened.** It uses a lightweight embedded database
   and single-instance abuse protections, and has no monitoring for suspicious activity. *Why not done
   here:* this is a larger build-out beyond a security-fix pass.

## Recommended next steps

1. **Rotate every previously-committed secret** and remove them from history; require all secrets to
   come from the managed vault (the deployment we provided already does this).
2. **Bring the notification service into scope:** require authentication, block requests to internal
   addresses, and rotate its key.
3. **Productionise:** move to a managed database, add distributed rate-limiting and account lockout, and
   centralise logging with alerts on unusual login and access activity. The automated security gates are
   already in place — keep them as mandatory merge blockers.

**In one line:** the crown-jewel exposures are fixed and guarded by automation; the remaining work is
operational (rotate secrets), one out-of-scope service, and standard production hardening.
