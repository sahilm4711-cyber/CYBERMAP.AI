"""Generate the Phase 8 learning-center JSON files.

Content is written here in the author's own words (paraphrases of
public security concepts, not copied text). Run once:
    python scripts/generate_learning_topics.py  (or import + main())
"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "learning"


def _topic(slug, title, beginner, intermediate, advanced, key_points,
           defensive_examples, related_cwe_ids, knowledge_check):
    return {
        "slug": slug,
        "title": title,
        "levels": {
            "beginner": beginner,
            "intermediate": intermediate,
            "advanced": advanced,
        },
        "key_points": key_points,
        "defensive_examples": defensive_examples,
        "related_cwe_ids": related_cwe_ids,
        "knowledge_check": knowledge_check,
    }


def _qc(question, options, answer_index, explanation):
    return {
        "question": question,
        "options": options,
        "answer_index": answer_index,
        "explanation": explanation,
    }


TOPICS = [
    _topic(
        "owasp_top_10",
        "OWASP Top 10 (2021) — The Ten Most Common Web Risks",
        "Think of a web app as a house. The OWASP Top 10 is a list of the ten ways burglars most often get in: unlocked doors, weak locks, hidden spare keys, and so on. You do not need to memorise every detail yet — just learn what each risk is called and why it matters.",
        "Each of the ten categories names a class of weakness, not a single bug. For every category you should be able to say: what the attacker gains, what code pattern causes it, and what the standard defence is. The categories overlap — one real vulnerability often fits two of them.",
        "Use the Top 10 as a review checklist and a threat-model input, not as a complete security standard. It ranks common, high-impact risks in typical web apps; your own app may have risks the list does not cover (business-logic abuse, for example). Map each category to concrete controls in your codebase and to tests that prove the controls work.",
        [
            "Broken Access Control — users reaching data or actions they should not.",
            "Cryptographic Failures — sensitive data exposed because it is not protected properly.",
            "Injection — untrusted input treated as code or commands.",
            "Insecure Design — security missing from the design itself, not just the code.",
            "Security Misconfiguration — unsafe defaults, open admin panels, verbose errors.",
            "Vulnerable and Outdated Components — known-buggy libraries left in place.",
            "Identification and Authentication Failures — weak or broken login and session handling.",
            "Software and Data Integrity Failures — trusting updates, plugins or data that were tampered with.",
            "Security Logging and Monitoring Failures — attacks happening unnoticed.",
            "Server-Side Request Forgery (SSRF) — the server tricked into making requests on the attacker's behalf.",
        ],
        [
            {
                "title": "Defence in depth, not one magic fix",
                "language": "text",
                "code": "Design review -> threat model -> secure defaults -> input validation -> least privilege -> logging -> tests -> patching",
                "explanation": "Each category is countered by a different layer. A checklist reviewed at design time catches more than a scanner run at the end.",
            },
            {
                "title": "Keep an inventory of your components",
                "language": "bash",
                "code": "# List installed packages and check them against known issues\npip list\nnpm audit\n# Pin versions and update on a schedule, not only after an incident",
                "explanation": "You cannot patch a library you do not know you use. An inventory plus a regular update routine addresses the outdated-components category.",
            },
        ],
        ["CWE-862", "CWE-863", "CWE-89", "CWE-79", "CWE-798"],
        [
            _qc(
                "Which OWASP Top 10 category covers a normal user viewing another user's private records by changing an ID in a URL?",
                ["Injection", "Broken Access Control", "Cryptographic Failures", "Security Misconfiguration"],
                1,
                "Changing an ID to reach someone else's data is an access-control failure: the app never checked whether this user was allowed to see that record.",
            ),
            _qc(
                "Why is the OWASP Top 10 a starting point rather than a complete security standard?",
                ["It only lists the ten most common high-impact web risks", "It is only about mobile apps", "It replaces all penetration testing", "It only applies to banks"],
                0,
                "It ranks common risks in typical web apps. Your app can still have business-logic or platform-specific risks the list does not describe.",
            ),
        ],
    ),
    _topic(
        "cwe_categories",
        "CWE Categories — How Weaknesses Are Classified",
        "CWE is a shared dictionary of software weaknesses. Instead of every team inventing its own names, everyone uses the same CWE numbers — CWE-79 always means the same kind of cross-site scripting weakness, wherever you read it.",
        "CWEs are organised into views and categories (for example, improper input validation, improper access control, improper handling of sensitive data). A single CVE usually maps to one or more CWEs, which tells you the root cause class, not just the symptom.",
        "Use CWE mappings to prioritise remediation by weakness class: if ten CVEs in your stack all map to improper input validation, fixing validation centrally (a shared library, a framework feature) beats patching ten symptoms one by one. Track which CWE classes recur in your own code reviews.",
        [
            "One CVE can map to several CWEs; one CWE explains many CVEs.",
            "CWE describes the weakness (root cause); CVE describes a specific instance in a product.",
            "Categories group related CWEs so teams can spot patterns.",
            "CWE IDs are stable references you can search in any vulnerability database.",
        ],
        [
            {
                "title": "Looking up a weakness class in your own data",
                "language": "python",
                "code": "# In CyberMap AI, a CVE links to its CWEs through\n# vulnerability_relationships with relationship='HAS_WEAKNESS'.\n# Group your findings by CWE to find the recurring root cause.",
                "explanation": "Grouping by CWE turns a long list of individual bugs into a short list of systemic problems to fix.",
            },
        ],
        ["CWE-20", "CWE-79", "CWE-89", "CWE-200"],
        [
            _qc(
                "What is the difference between a CVE and a CWE?",
                ["A CVE is a specific instance in a product; a CWE is the weakness class", "They are the same thing", "A CVE is a fix and a CWE is a bug", "A CWE only applies to hardware"],
                0,
                "CVE-2024-12345 names one flaw in one product. CWE-79 names the whole class of cross-site scripting weaknesses that many CVEs share.",
            ),
            _qc(
                "Why group findings by CWE category instead of fixing CVEs one by one?",
                ["It reveals a recurring root cause you can fix once, centrally", "It hides the real bugs", "It is required by law everywhere", "It makes the list longer"],
                0,
                "Ten CVEs sharing one CWE usually share one root cause. Fix the cause and the whole class shrinks.",
            ),
        ],
    ),
    _topic(
        "secure_coding",
        "Secure Coding — Habits That Prevent Whole Bug Classes",
        "Secure coding is mostly habit, not cleverness: never trust input from outside your code, fail closed when something is unexpected, and use the safe tool the framework already gives you instead of building your own.",
        "The highest-value habits are: validate and encode at boundaries, use parameterised queries, keep secrets out of code, handle errors without leaking internals, and write the smallest amount of privileged code you can. Each habit removes a whole class of bugs rather than one bug.",
        "Treat security as a property of the design: define trust boundaries, decide what each component is allowed to do, and make the unsafe path the hard path (safe defaults, allow-lists, typed APIs). Review for the pattern, not the incident — and automate the check (linters, dependency scans, tests) so the habit survives deadlines.",
        [
            "Validate input at the boundary; encode output for its context.",
            "Use parameterised queries — never build SQL from string concatenation.",
            "Fail closed: when in doubt, deny and log, do not allow.",
            "Never hard-code secrets; load them from a vault or environment.",
            "Keep error messages generic for users and detailed only in server logs.",
        ],
        [
            {
                "title": "Parameterised query (safe) vs string building (unsafe)",
                "language": "python",
                "code": "# SAFE: the database treats the value as data, never as SQL.\ncur.execute(\"SELECT * FROM users WHERE username = %s\", (username,))\n\n# UNSAFE — do not do this:\n# cur.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
                "explanation": "Parameterisation separates code from data. The unsafe version lets input rewrite the query itself.",
            },
            {
                "title": "Output encoding for HTML context",
                "language": "python",
                "code": "import html\nsafe = html.escape(user_comment)  # < becomes &lt; and so on",
                "explanation": "Encoding at output time means user text is displayed as text, never interpreted as markup or script.",
            },
        ],
        ["CWE-89", "CWE-79", "CWE-20", "CWE-798"],
        [
            _qc(
                "Why is a parameterised query safer than building SQL with string concatenation?",
                ["The database treats the value as data, never as SQL code", "It runs faster", "It hides the table name", "It encrypts the value"],
                0,
                "With parameters, user input can never change the structure of the query — it stays data, so injection is not possible through that path.",
            ),
            _qc(
                "What does 'fail closed' mean?",
                ["When something is unexpected, deny access and log it", "Close the application on every error", "Hide all errors from everyone", "Allow access but warn the user"],
                0,
                "Failing closed means the default outcome of an error or ambiguity is denial, not access.",
            ),
        ],
    ),
    _topic(
        "auth_weaknesses",
        "Identification and Authentication Failures",
        "Login is the front door. Authentication failures happen when the door can be opened without the right key: weak passwords allowed, no limit on guesses, sessions that never expire, or password-reset links that can be guessed.",
        "Common patterns: credential stuffing against logins with no rate limiting, weak password policies, session tokens that are predictable or never invalidated after logout or password change, and multi-factor authentication missing on privileged accounts.",
        "Defend in layers: strong, breached-password-checked credentials; rate limiting and lockout with care for denial-of-service; random, expiring, revocable session tokens stored hashed server-side; MFA for admin and sensitive actions; and a password-reset flow whose tokens are random, single-use and short-lived.",
        [
            "Allow long passphrases; check new passwords against known breach lists.",
            "Rate-limit login attempts per account and per IP; log failures.",
            "Session tokens must be random, expire, and be revocable on logout and password change.",
            "Require MFA for privileged accounts and sensitive actions.",
            "Password-reset tokens: random, single-use, short-lived, sent only to the registered address.",
        ],
        [
            {
                "title": "Store only a strong hash, never the password",
                "language": "python",
                "code": "from argon2 import PasswordHasher\nph = PasswordHasher()\nstored = ph.hash(plain_password)   # store `stored`, never the password\nph.verify(stored, plain_password)  # raises on mismatch",
                "explanation": "Argon2id is a memory-hard hash designed for passwords. If the database leaks, attackers still face a slow, expensive guess for every password.",
            },
            {
                "title": "Session cookie flags (defensive configuration)",
                "language": "text",
                "code": "Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800",
                "explanation": "HttpOnly keeps scripts from reading the token, Secure sends it only over HTTPS, and SameSite=Lax limits cross-site sending.",
            },
        ],
        ["CWE-307", "CWE-798", "CWE-384", "CWE-521"],
        [
            _qc(
                "An attacker tries thousands of passwords against one account and the app never slows them down. Which weakness is this?",
                ["Missing rate limiting / improper restriction of authentication attempts", "Cross-site scripting", "SQL injection", "Insecure deserialisation"],
                0,
                "Unlimited guesses make brute force and credential stuffing practical. Rate limiting and lockout are the standard countermeasures.",
            ),
            _qc(
                "After a user changes their password, what should happen to their other active sessions?",
                ["They should be revoked, forcing re-login", "Nothing — they stay valid forever", "They should be made admin sessions", "They should be shared with the user by email"],
                0,
                "A password change usually means the account may be compromised, so other sessions must be invalidated.",
            ),
        ],
    ),
    _topic(
        "access_control",
        "Broken Access Control",
        "Access control answers one question: is this user allowed to do this thing to this object? It breaks when the app forgets to ask — a normal user opening an admin page, or viewing someone else's record by changing an ID.",
        "The classic patterns are insecure direct object references (predictable IDs with no ownership check), missing function-level checks (the button is hidden but the API endpoint is open), and privilege escalation through a parameter the user controls.",
        "Enforce authorisation on the server for every request, using the authenticated identity and the object's owner — never trust a hidden form field or a client-side check. Prefer deny-by-default: every endpoint starts closed and explicitly grants what a role may do. Test with two accounts: what user B can do to user A's data is the test that matters.",
        [
            "Check ownership on the server for every object access, not only in the UI.",
            "Deny by default; grant explicitly per role and per action.",
            "Never trust IDs, roles or permissions sent by the client.",
            "Use unpredictable IDs where possible, but never rely on secrecy alone.",
            "Audit access decisions — log denied attempts.",
        ],
        [
            {
                "title": "Ownership check on the server (pattern)",
                "language": "python",
                "code": "# Every single-object read must do this:\nobj = db.query(Note).filter(Note.id == note_id).first()\nif obj is None or obj.user_id != current_user.id:\n    raise HTTPException(404, \"Not found\")  # 404, not 403: do not leak existence",
                "explanation": "Returning 404 for another user's object hides whether it exists at all, and the check happens server-side where the client cannot bypass it.",
            },
        ],
        ["CWE-862", "CWE-863", "CWE-639", "CWE-284"],
        [
            _qc(
                "A page hides the 'Delete' button from normal users, but the delete API endpoint works without any role check. What is wrong?",
                ["Authorisation must be enforced on the server; hiding UI is not a control", "The button should be bigger", "The API needs a faster database", "Nothing — users cannot find hidden buttons"],
                0,
                "Anyone can call an API directly. The server must check the caller's role on every request, regardless of what the UI shows.",
            ),
            _qc(
                "Why return 404 instead of 403 when a user requests another user's private object?",
                ["So an attacker cannot learn whether the object exists", "Because 403 is slower", "Because 404 is the only valid code", "To confuse legitimate users"],
                0,
                "A 403 confirms the object exists but is forbidden; a 404 reveals nothing, which prevents probing for other users' data.",
            ),
        ],
    ),
    _topic(
        "crypto_failures",
        "Cryptographic Failures",
        "Cryptography fails most often not because the maths is broken, but because it is used wrongly: passwords stored in plain text, sensitive data sent without TLS, old algorithms kept running, or keys left in source code.",
        "Watch for: data in transit without TLS, sensitive data at rest unencrypted, weak or outdated algorithms (MD5/SHA-1 for passwords, DES, RC4), hard-coded keys and secrets, and random numbers from a non-cryptographic generator used for tokens.",
        "Rules that cover most cases: TLS everywhere with modern configuration; encrypt sensitive data at rest with a managed key; hash passwords with Argon2id/bcrypt/scrypt; use a vetted library and a cryptographic random generator for tokens and keys; rotate keys and never commit them.",
        [
            "TLS for all traffic; no sensitive data over plain HTTP.",
            "Hash passwords with a purpose-built password hash (Argon2id), never MD5/SHA-1.",
            "Use a vetted crypto library; do not design your own cipher or protocol.",
            "Keys and secrets live in a vault or environment, never in code or git.",
            "Use a cryptographic random source for tokens, salts and keys.",
        ],
        [
            {
                "title": "Cryptographically secure random token",
                "language": "python",
                "code": "import secrets\ntoken = secrets.token_urlsafe(32)  # random, URL-safe, suitable for session/reset tokens",
                "explanation": "The secrets module uses the operating system's secure random source. The random module is for simulations, not security tokens.",
            },
            {
                "title": "Password hashing, not encryption",
                "language": "python",
                "code": "# Passwords are HASHED (one-way) with Argon2id, not encrypted.\n# Encryption is reversible with a key; a hash cannot be reversed,\n# so a database leak does not hand attackers the passwords.",
                "explanation": "Hashing is the right tool for passwords because the server never needs to recover the original password — it only needs to check a guess.",
            },
        ],
        ["CWE-798", "CWE-327", "CWE-338", "CWE-311"],
        [
            _qc(
                "Which is the correct way to store user passwords?",
                ["Hash with Argon2id/bcrypt/scrypt", "Store in plain text for recovery", "Encrypt with a key in the same database", "Hash with MD5"],
                0,
                "A memory-hard password hash is one-way and slow to guess. Plain text, reversible encryption and fast hashes like MD5 all fail when the database leaks.",
            ),
            _qc(
                "Why should session tokens come from a cryptographic random source?",
                ["So they cannot be predicted or guessed by an attacker", "So they are shorter", "So they work offline", "So they never expire"],
                0,
                "Predictable tokens let an attacker forge a session. A secure random source makes guessing infeasible.",
            ),
        ],
    ),
    _topic(
        "misconfiguration",
        "Security Misconfiguration",
        "Misconfiguration is the 'left the door open' category: default passwords unchanged, admin panels exposed to the internet, debug mode on in production, error pages that reveal internals, or cloud storage buckets left public.",
        "Typical causes: shipping with vendor defaults, enabling features nobody needs, verbose errors and stack traces in production, missing security headers, and infrastructure changed by hand instead of reviewed code.",
        "Counter it with a hardened baseline: change every default credential, disable what you do not use, keep production and development settings separate, return generic errors to users, set security headers, and review infrastructure changes like code changes.",
        [
            "Change all default credentials before first use.",
            "Disable debug mode, directory listings and unused features in production.",
            "Return generic errors to users; keep detail in server logs.",
            "Set security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).",
            "Define infrastructure as reviewed code, not manual clicks.",
        ],
        [
            {
                "title": "Defensive security headers (example values)",
                "language": "text",
                "code": "Content-Security-Policy: default-src 'self'\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nReferrer-Policy: no-referrer",
                "explanation": "Headers are cheap, central defences: they limit what the browser will load and execute, and stop the site being framed by another page.",
            },
            {
                "title": "Separate dev and production settings",
                "language": "python",
                "code": "# Production must never inherit development settings:\n# DEBUG = False in production; error pages generic;\n# secrets from the environment, never from a checked-in file.",
                "explanation": "Most misconfigurations are a development setting that leaked into production. Make the two environments structurally different, not just a flag someone might forget.",
            },
        ],
        ["CWE-1188", "CWE-200", "CWE-798", "CWE-16"],
        [
            _qc(
                "A production error page shows a full stack trace with file paths and database details. Which category is this?",
                ["Security Misconfiguration (and information exposure)", "Injection", "Broken Access Control", "SSRF"],
                0,
                "Verbose errors in production leak internals that help an attacker. Users get a generic message; detail stays in server logs.",
            ),
            _qc(
                "What is the best first step against misconfiguration across many servers?",
                ["A hardened, reviewed baseline applied everywhere, with drift checks", "A different password on each server, remembered by staff", "Disabling all logging", "Leaving vendor defaults and patching later"],
                0,
                "A single reviewed baseline plus automated checks that detect drift beats fixing each server by hand after the fact.",
            ),
        ],
    ),
    _topic(
        "defensive_testing",
        "Defensive Testing — Proving Your Controls Work",
        "A control you have never tested is a hope, not a defence. Defensive testing means deliberately checking that the protections you built actually stop the bad case: the wrong user, the bad input, the expired token.",
        "Useful test types: unit tests for validation and authorisation helpers; integration tests that log in as user B and try to touch user A's data (expect 404); dependency and secret scans in CI; and header/configuration checks against a live staging deployment.",
        "Make the tests part of the pipeline so they run on every change: a test that only runs when someone remembers to run it will be skipped exactly when it matters. Record the result — a passing security test is evidence you can show, not just a feeling.",
        [
            "Test the negative case: user B vs user A's data must fail.",
            "Test expired, revoked and tampered tokens, not only valid ones.",
            "Scan dependencies and secrets automatically in CI.",
            "Check security headers and TLS on staging, not only in code review.",
            "Keep the tests in the pipeline so they run on every change.",
        ],
        [
            {
                "title": "Isolation test pattern (two users, one object)",
                "language": "python",
                "code": "register_user(client, 'alice'); register_user(client, 'bob')\nlogin_user(client, 'alice')\nnote = client.post('/api/v1/research/notes', json={...}).json()\nlogin_user(client, 'bob')\nresp = client.get(f\"/api/v1/research/notes/{note['id']}\")\nassert resp.status_code == 404  # B must not see A's note",
                "explanation": "This is the exact pattern Phase 8 uses: create as A, switch to B, expect 404. It catches missing ownership checks immediately.",
            },
        ],
        ["CWE-862", "CWE-863", "CWE-307"],
        [
            _qc(
                "Why test with a second user account instead of only checking your own access works?",
                ["Because the critical failure is another user reaching your data", "Because one account is slower", "Because tests need two names", "Because the database requires it"],
                0,
                "Your own access working proves nothing about isolation. The B-tries-A's-data test is the one that catches missing ownership checks.",
            ),
            _qc(
                "Where should security tests run so they are not skipped under pressure?",
                ["Automatically in CI on every change", "Only before a major release", "Only on the developer's laptop", "Nowhere — manual checks are enough"],
                0,
                "Automated pipeline tests run every time, including the rushed change on a Friday. Manual checks get skipped exactly then.",
            ),
        ],
    ),
    _topic(
        "remediation",
        "Remediation — Fixing, Verifying and Prioritising",
        "Remediation is the work after a finding: understand the root cause, fix it at the right layer, prove the fix works, and make sure the same bug cannot come back quietly.",
        "Prioritise by real risk, not only by score: exploitability (is it reachable? is there a public exploit? is it in CISA KEV?), exposure (internet-facing? sensitive data?), and blast radius. A medium bug on an internet-facing login page can matter more than a critical bug in an unused internal tool.",
        "Fix at the root-cause layer when you can (a shared validation library beats ten one-off patches), add a regression test that fails if the bug returns, and track the fix to closure with a due date — KEV entries even carry a due date for exactly this reason.",
        [
            "Prioritise by exploitability + exposure + data at risk, not score alone.",
            "Fix the root cause at the shared layer where possible.",
            "Add a regression test that fails if the bug returns.",
            "Verify the fix in staging with the same test that found the bug.",
            "Track remediation to closure with an owner and a due date.",
        ],
        [
            {
                "title": "A remediation checklist for one finding",
                "language": "text",
                "code": "1. Reproduce the finding in a lab (never on production data)\n2. Identify the root cause and the layer to fix\n3. Fix + add a regression test\n4. Re-run the original test — it must now fail to exploit\n5. Review, deploy, and record closure with date + owner",
                "explanation": "Step 4 is the one teams skip: without re-running the original test, you have a change, not a verified fix.",
            },
        ],
        ["CWE-20", "CWE-89", "CWE-79", "CWE-862"],
        [
            _qc(
                "A critical-severity bug sits in an unused internal tool, and a medium bug sits on the public login page. Which do you fix first?",
                ["Usually the medium bug on the public login page — it is reachable and exploitable", "Always the critical one, scores decide everything", "Neither — wait for the next release", "The one with the shorter CVE ID"],
                0,
                "Severity scores do not include your exposure. Reachability, exploitability and data at risk decide real priority.",
            ),
            _qc(
                "Why add a regression test as part of a fix?",
                ["So the bug is caught automatically if it ever comes back", "To make the fix slower", "To replace code review", "Because tests are required for the CVE to close"],
                0,
                "Without a regression test, a later refactor can silently reintroduce the same weakness and nobody notices until the next incident.",
            ),
        ],
    ),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for topic in TOPICS:
        path = OUT / f"{topic['slug']}.json"
        path.write_text(json.dumps(topic, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path} ({len(topic['knowledge_check'])} questions)")


if __name__ == "__main__":
    main()
