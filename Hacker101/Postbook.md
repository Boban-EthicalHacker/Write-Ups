# Postbook - Hacker101 CTF

Platform: Hacker101 CTF
Difficulty: Easy
Category: Web
Flags: 7/7
Date: 20.10.2026.

---

## Overview

Postbook is a small blogging application where users can register, sign in, and create public or private posts. Private posts are supposed to be visible only to their author. The challenge description promises that private posts are "safe with us", which is exactly the kind of claim that makes a security tester suspicious.

The goal was to retrieve seven flags, each one hidden behind a different weakness in the application. What I found was a chain of classic web vulnerabilities that all share the same root cause: the server trusted the client too much.

---

## Reconnaissance

Before touching anything, I did what I always do with a new target. I clicked around and watched what the application sent me.

A few things immediately stood out:

- Every post had a URL like `?page=view.php&id=3`. The `id` was a small sequential number. That is a red flag on its own because if IDs are predictable, an attacker can enumerate them.
- Signing up was trivial and the app did not enforce any password policy.
- After login, a cookie named `id` was set. The value was a 32-character hex string, which is clearly an MD5 hash.
- The delete link for a post contained the same MD5 hash of the post ID in the URL, not the number itself.

Those four observations alone told me where to focus.

---

## Flag 0 - Weak password

### What I did

The hint said the user `user` had a "very easy password". I signed in as `user` with `password` on the first try.

### Why it worked

The application allowed registration with the most common password on the planet. No complexity rules, no minimum length, no check against known breached passwords. Combined with no rate limiting on the login endpoint, this account could be brute-forced in seconds even without the hint.

### How to prevent it

- Enforce a reasonable password policy. Length over complexity. NIST SP 800-63B recommends a minimum of 8 characters and a check against a breached-password list.
- Add rate limiting and account lockout on the login endpoint.
- Offer MFA.
- Ban known weak passwords by checking against the HaveIBeenPwned top-list on registration.

---

## Flag 1 - IDOR on read (view someone else's post)

### What I did

I opened my own post. The URL was `?page=view.php&id=3`. I changed `id=3` to `id=2` and the application showed me a post written by `admin`, including a private one ("SECRET: Dear diary...").

### Why it worked

The server checked that I was logged in, but it never checked whether the post belonged to me. The query was essentially:

```sql
SELECT * FROM posts WHERE id = 2;
```

instead of:

```sql
SELECT * FROM posts
WHERE id = 2
  AND (owner_id = :current_user OR is_private = 0);
```

This is a textbook Insecure Direct Object Reference (IDOR). The application exposes an internal identifier and lets the client decide which object to fetch. Because IDs were small sequential numbers, I could also have scripted this and dumped every post in the database in a few seconds.

### How to prevent it

- Authorize on the server for every request. Never assume that because a user is authenticated, they are allowed to access the resource.
- Prefer unpredictable identifiers (UUID v4) over auto-incremented integers.
- If IDs must remain numeric, use an indirect reference map. The client sends a token, the server maps it to the real ID internally.
- Log and alert on anomalous access patterns, for example one user reading 10,000 posts in a minute.

---

## Flag 2 - Mass assignment (creating a post as admin)

### What I did

The hint told me to use "Inspect Element" on the new-post form. When I looked, I saw a hidden input:

```html
<input type="hidden" name="user_id" value="2">
```

I changed `2` to `1` (the admin's ID) and submitted the form. The post was created as if it had been written by the administrator.

### Why it worked

The server trusted the client to send the correct `user_id`. It took the value straight from `$_POST` and wrote it into the database, instead of pulling the ID from the authenticated session.

The hidden field is not a security control. It is just a UI convenience. Anyone with a browser can modify it.

### How to prevent it

- Never trust user identifiers coming from the client. The owner of a new record is the authenticated user in the current session:

```php
$post->user_id = $_SESSION['user_id'];   // correct
$post->user_id = $_POST['user_id'];      // wrong
```

- If the application has roles, apply a whitelist of fields that can be mass-assigned. In frameworks this is Laravel's `$fillable`, Rails' `permit`, or Spring's `@JsonIgnore`.
- Explicitly reject any field the user is not allowed to set.

---

## Flag 3 - Predictable identifiers (enumerating IDs)

### What I did

The hint was a math expression: `189 * 5`. I computed `945`, replaced the `id` in the URL with `945`, and a special post appeared.

### Why it worked

The same root cause as Flag 1, but this flag specifically demonstrates enumerability. Because IDs are sequential (1, 2, 3, ... 945, ...), an attacker does not need to know the exact ID. They can brute-force the entire space with a simple script:

```python
for i in range(1, 10000):
    r = requests.get(f"{base}?page=view.php&id={i}",
                     cookies=session_cookies)
    if "FLAG" in r.text:
        print(i, r.text)
```

That is why security professionals insist on unpredictable IDs. They turn enumeration from a trivial loop into an impractical search.

### How to prevent it

- Use UUID v4 (128-bit, effectively unguessable) for public-facing identifiers.
- Enforce authorization regardless. UUIDs are not a replacement for access control, they just raise the cost of guessing.
- Add rate limiting on the API endpoint.

---

## Flag 4 - IDOR on write (editing someone else's post)

### What I did

I clicked "edit" on one of my own posts. The URL was `?page=edit.php&id=3`. I changed `id=3` to `id=1` (the admin's post). The edit form opened, pre-populated with the admin's content. I changed the text and saved. The flag appeared.

### Why it worked

Exactly the same flaw as Flag 1, but on a write operation. The application checked authentication but not ownership. This is more dangerous than read-IDOR because it lets an attacker:

- Destroy or deface another user's data.
- Inject stored XSS into a post that other users, including admins, will view.
- Take over another user's identity inside the application.

### How to prevent it

- Enforce ownership on every state-changing action:

```php
if ($post->user_id !== $_SESSION['user_id']) {
    http_response_code(403);
    exit("Forbidden");
}
```

- Do not rely on "the button is not visible in the UI". The endpoint is still reachable.
- Add CSRF tokens to all state-changing forms as a separate layer, not a substitute for authorization.

---

## Flag 5 - Session cookie tampering (becoming admin)

### What I did

In DevTools, under Application and Cookies, I found a cookie called `id` with the value:

```
c81e728d9d4c2f636f067f89cc14862c
```

An MD5 decoder told me this was the hash of `2`, which was my user ID. So the application was storing my identity in the cookie as a bare MD5 hash of my numeric ID.

I computed MD5("1"):

```
c4ca4238a0b923820dcc509a6f75849b
```

Replaced the cookie value, refreshed the page, and was logged in as the administrator.

### Why it worked

Several problems compounded:

1. The session identifier is the user ID itself, only hashed. The server uses the cookie as the single source of identity.
2. MD5 is fast and predictable, and there is no salt or secret key. MD5("1") is the same on every machine in the world.
3. There is no integrity check. No HMAC signature, so the client can change the value freely.
4. Cookies are client-controlled. The user can always edit them in DevTools.

This is a classic example of security through obscurity. The developer probably thought nobody would realise it is an MD5 hash. Attackers realise.

### How to prevent it

- Never store user identity in a client-controlled value. Use a server-side session with a random, opaque session ID, for example 128-bit from a CSPRNG.
- If a stateless token is required (JWT), sign it with HMAC-SHA256 or RSA and verify the signature on every request.
- Store cookies with HttpOnly, Secure, and SameSite=Strict.
- Rotate the session ID on login and privilege change, as session fixation protection.
- Use a modern, salted password hashing scheme such as bcrypt or argon2. MD5 is not acceptable for anything security-relevant.

---

## Flag 6 - Deleting someone else's post via MD5 token

### What I did

The hint said the delete function took "an ID that is not a number". Inspecting the delete link on my own post:

```html
<a href="index.php?page=delete.php&id=c81e728d9d4c2f636f067f89cc14862c">
```

Again the MD5 of the post ID. I computed MD5 for the admin's post and requested:

```
/index.php?page=delete.php&id=eccbc87e4b5ce2fe28308fd9f2a7baf3
```

The post was deleted and the flag appeared.

### Why it worked

The developer seemed to think that hashing the ID made it a secret token only the owner would know. But:

1. MD5 is a public algorithm. Anyone can compute it.
2. There is no secret key. It is not HMAC.
3. The input space is tiny (integers 1 to N), so you can precompute the entire rainbow table in a second.
4. Ownership was never verified. The server accepted any valid hash.

So this is effectively the same bug as Flag 4 (write-IDOR), dressed up in bad cryptography.

### How to prevent it

- Authorization first. Check that the current user owns the post. The hash is irrelevant if ownership is enforced.
- If a token is genuinely needed, sign it with a server-side secret:

```php
$token = hash_hmac('sha256', $post_id, $SECRET_KEY);
```

Now the attacker cannot compute the token without the key.

- Add CSRF tokens for all destructive actions.
- Consider soft delete (mark as deleted, keep the row) so accidental or malicious deletions can be recovered.

---

## Root cause analysis

Looking back at all seven flags, they are not seven unrelated bugs. They are variations on two themes.

### 1. The server trusted the client

- `user_id` from the form (Flag 2).
- `id` from the cookie (Flag 5).
- `id` from the URL (Flags 1, 3, 4, 6).

Every single one of these would have been harmless if the server had derived the values itself from the authenticated session and verified ownership on every action.

### 2. Weak cryptography was used as authorization

- MD5 without a salt (Flag 5).
- MD5 without a secret key (Flag 6).

Hashing is not a substitute for access control. Cryptography protects confidentiality and integrity against an attacker who does not hold the key. If there is no key, there is no protection.

---

## What I took away from this challenge

1. Authorization is not authentication. Being logged in does not mean being allowed to do everything. Every endpoint needs an ownership or role check, on the server, on every request.
2. Client input is hostile input. URLs, forms, cookies, and headers are all attacker-controlled. Any value that matters for security must be derived server-side.
3. Unpredictable identifiers raise the cost of attack. Sequential integers invite enumeration. UUIDs make it impractical.
4. "Hidden" is not "secure". Hidden form fields, hashed IDs, and MD5 tokens are obfuscation at best.
5. Never roll your own crypto. If you need a token, use HMAC with a secret key. If you need to hash a password, use bcrypt or argon2. Do not invent a scheme.
6. The order of operations matters. Authorization checks must run before the query, not after the data has already been returned.

---

## References

- OWASP Top 10 - A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP - Insecure Direct Object Reference: https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes: https://cwe.mitre.org/data/definitions/915.html
- CWE-330: Use of Insufficiently Random Values: https://cwe.mitre.org/data/definitions/330.html
- CWE-916: Use of Password Hash With Insufficient Computational Effort: https://cwe.mitre.org/data/definitions/916.html
- NIST SP 800-63B - Digital Identity Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html
