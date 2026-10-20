# Micro-CMS v2 - Hacker101 CTF

Platform: Hacker101 CTF
Difficulty: Moderate
Category: Web
Flags: 3/3
Date: (upisi datum)

---

## Overview

Micro-CMS v2 is the follow-up to Micro-CMS v1. It is a small content management system with a login form, a list of public pages, and an admin area that is supposed to be reachable only to authenticated users. The goal was to retrieve three flags. Each flag required a different technique: SQL injection in the login form, a POST request to an endpoint that only checked authorization for GET, and extraction of the real admin credentials from the database.

The three flags are not three independent bugs. They are three paths into the same application, each of which exploits a different missing control. Together they show how a single web application can be compromised from several directions when input handling and authorization are not applied consistently.

---

## Reconnaissance

The application exposed a small set of routes:

- `/` - list of public pages
- `/page/N` - view a page by numeric ID
- `/page/create` - create a new page (reachable only when logged in)
- `/page/edit/N` - edit a page (reachable only when logged in)
- `/login` - login form

The home page listed two public pages. The first hint said: "Regular users can only see public pages. Getting admin access might require a more perfect union."

The phrase "more perfect union" is a direct reference to UNION-based SQL injection. That was the first thing to test.

Submitting a single quote in the username field returned a 500 Internal Server Error, while submitting any normal username returned 200 with "Unknown user". That difference confirmed that the username field was concatenated into a SQL query.

---

## Flag 0 - SQL injection authentication bypass

### What I did

I sent the following payload in the username field of the login form:

```
' UNION SELECT 'pass' AS password FROM admins WHERE '1' = '1
```

and used the password `pass`.

The application accepted the login. The home page then displayed a link to the admin area, and the first flag was inside it.

### Why it worked

The login query was built by string concatenation, most likely something like:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```

With the payload above, the query becomes:

```sql
SELECT * FROM users WHERE username = '' UNION SELECT 'pass' AS password FROM admins WHERE '1' = '1' AND password = 'pass';
```

The UNION appends a row with a password value of `pass`. The application checks only whether a row was returned, not whether the row came from the users table, so the authentication check passes. The username column in that row is empty, which is why the application treated the session as authenticated but not as a specific user.

The table name `admins` was not visible anywhere in the UI. It was guessed from the challenge context and confirmed by the fact that the payload returned a row.

### How to prevent it

- Use parameterized queries (prepared statements) for every database access. Never concatenate user input into SQL.
- Return generic error messages. A 500 on a single quote is a gift to an attacker.
- Enforce the table the query is supposed to read from. If the login query is supposed to look only at users, a UNION should not be able to inject rows from other tables.
- Add rate limiting and alerting on requests that contain SQL keywords such as UNION, SELECT, or comment sequences in form fields.

---

## Flag 1 - Improper HTTP method handling

### What I did

The second hint said: "What actions could you perform as a regular user on the last level, which you can't now?" and "Just because request fails with one method doesn't mean it will fail with a different method."

In Micro-CMS v1, a logged-in user could reach `/page/edit/N` directly. In v2, the GET request to that route returned 403 or a redirect, because the application had added a session check. However, the route itself was still registered for multiple HTTP methods.

I sent a POST request to the same route with curl:

```bash
curl -i -X POST "https://<host>/page/edit/1"
```

The response was 200 and contained the second flag.

### Why it worked

The application enforced authentication on the GET handler but not on the POST handler. The edit endpoint accepted both methods, and only one of them checked the session. Switching the method bypassed the check entirely.

This pattern is common in frameworks that map different HTTP verbs to different handlers. Developers often protect the handler they are testing (usually GET) and forget that the same resource is reachable through other verbs.

### How to prevent it

- Enforce authorization in a central middleware or filter that runs for every request to a protected resource, regardless of method.
- If a route should only accept GET, reject other methods explicitly. Do not leave POST, PUT, PATCH, or DELETE enabled by accident.
- Review the full method mapping for every route. A route that exists in the framework's route table is a route that can be reached.
- Add tests that send every HTTP method to every route and verify that unauthorized methods are rejected.

---

## Flag 2 - Extracting admin credentials with blind SQL injection

### What I did

The third hint said: "Credentials are secret, flags are secret. Coincidence?" That pointed at the database itself. The real admin username and password were stored in a table, and the same SQL injection that allowed the authentication bypass could also be used to read them.

I tried UNION-based extraction first, but the UNION tests were inconsistent: sqlmap reported a potential UNION injection, then discarded it after a fuzzy test. The application returned 500 on some UNION payloads and 200 on others, which suggested that UNION was unreliable on this endpoint. So I fell back to the time-based blind technique.

I used sqlmap with the following options:

```bash
sqlmap -u "https://<host>/login" \
  --data "username=?&password=pass" \
  -p username \
  --technique=T \
  --time-sec=1 \
  -D level2 \
  -T admins \
  --dump \
  --batch \
  --random-agent \
  --timeless
```

The important details:

- `--technique=T` limits sqlmap to time-based blind. This avoids the flaky UNION tests.
- `--time-sec=1` shortens the delay between requests, which speeds up extraction.
- `--timeless` uses HTTP/2 response ordering instead of SLEEP delays. On this target it was significantly faster than the default time-based method.
- `-D level2 -T admins` scopes the dump to the specific database and table, which avoids dumping the entire schema.

sqlmap identified the injection point as a MySQL time-based blind in the username parameter, enumerated the `admins` table, and returned one row with a username and a password.

I then logged in with those credentials through the normal login form. The admin area opened and the third flag appeared.

### Why it worked

The login endpoint was vulnerable to SQL injection. The application returned different responses depending on whether the injected condition was true or false, which is enough for a blind SQL injection attack. An attacker can ask the database yes or no questions and reconstruct the contents of any table one character at a time.

The extraction was slow because each character required a separate request. The `--timeless` option made it practical by using HTTP/2 response ordering rather than waiting for a SLEEP delay on every request.

The deeper problem is the same as Flag 0: user input was concatenated into the SQL query. The password was stored in the database in a form that sqlmap could recover directly, which means it was either plaintext or hashed with a weak, unsalted function. Either way, the credentials were usable after extraction.

### How to prevent it

- The same fix as Flag 0: parameterized queries for every database access.
- Store passwords with a modern password hashing algorithm such as bcrypt or argon2. Even if the database is dumped, the passwords should not be recoverable in a usable form.
- Do not store plaintext passwords. The fact that sqlmap dumped a password that worked on the login form means the application was not hashing them properly.
- Add rate limiting on the login endpoint. Blind SQL injection requires thousands of requests; a rate limit makes it impractical.
- Log and alert on requests that take an unusually long time or that contain SQL keywords in unexpected places.

---

## Root cause analysis

All three flags come from the same design mistake: the application trusted input that it did not control.

Flag 0 and Flag 2 are the same SQL injection, exploited in two different ways. Flag 0 used it to bypass authentication; Flag 2 used it to read the credentials of a real admin. Fixing the injection with parameterized queries would have prevented both. Storing passwords with a proper hash would have limited the impact of Flag 2 even if the injection existed.

Flag 1 is a separate issue: authorization was applied to one HTTP method but not another. The edit endpoint was protected against unauthenticated GET requests but not against unauthenticated POST requests.

The three flags together illustrate a common pattern in real applications. A single missing control (input sanitization) can lead to multiple distinct exploits, and a second missing control (method-level authorization) can open a completely different path. Fixing only the endpoint that was reported leaves the other paths open.

---

## What I took away from this challenge

1. A 500 error on a single quote is a SQL injection. When an application returns a server error instead of a validation message, it is telling the attacker that the input reached the database.

2. UNION is not always reliable. On this target, UNION detection gave a false positive that sqlmap discarded after a fuzzy test. Falling back to time-based blind was the correct decision. Do not trust the first detection result without confirmation.

3. HTTP method matters. Protecting GET does not protect POST. Every method that reaches a resource must enforce the same authorization rules.

4. Passwords must be hashed with a modern algorithm. If the database is dumped, plaintext or weakly hashed passwords turn a data breach into an account takeover. In this challenge, the extracted password worked directly on the login form.

5. Tools amplify manual findings. sqlmap did in minutes what would have taken hours by hand, but it only worked because the manual test (single quote) had already confirmed the injection. The tool is not a replacement for understanding the target.

6. Blind SQL injection is practical. The fact that responses are slow does not make an injection unexploitable. With enough requests, any table can be reconstructed one character at a time. Rate limiting is the only real defense against this class of attack after the injection itself is fixed.

7. The hints in Hacker101 are precise. "More perfect union" meant UNION injection. "Just because request fails with one method doesn't mean it will fail with a different method" meant method switching. "Credentials are secret, flags are secret" meant that the credentials were the target. Reading the hints carefully saved time.

---

## References

- OWASP - SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP - SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP - Blind SQL Injection: https://owasp.org/www-community/attacks/Blind_SQL_Injection
- PortSwigger - SQL Injection UNION Attacks: https://portswigger.net/web-security/sql-injection/union-attacks
- CWE-89: SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- CWE-285: Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
- CWE-650: Trusting HTTP Permission Methods on the Server Side: https://cwe.mitre.org/data/definitions/650.html
- CWE-916: Use of Password Hash With Insufficient Computational Effort: https://cwe.mitre.org/data/definitions/916.html
