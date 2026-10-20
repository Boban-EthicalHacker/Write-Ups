# Oauthbreaker - Hacker101 CTF

Platform: Hacker101 CTF
Difficulty: Moderate
Category: Android
Flags: 2/2
Date: (upisi datum)

---

## Overview

Oauthbreaker is an Android application that implements a simplified OAuth flow. The app opens a WebView, sends the user to an OAuth server, and receives a token at the end. The goal was to retrieve two flags. The first flag was hidden behind a redirect_uri manipulation in the OAuth flow. The second flag was hidden behind a JavaScript interface exposed inside a WebView that the attacker could control.

Both flags were solved without running the application on a device or emulator. The APK was decompiled with jadx and apktool, the manifest was read directly, and the relevant logic was reimplemented in Python. This write-up explains what the code showed, why each weakness was exploitable, and how to fix it.

---

## Reconnaissance

The APK was decompiled in two steps:

```bash
jadx -d ~/Projects/oauth-src ~/Projects/oauth.apk
apktool d ~/Projects/oauth.apk -o ~/Projects/oauth-apktool -f
```

jadx produced readable Java source. apktool produced the smali code and resources needed to resolve R.styleable constants.

The AndroidManifest.xml revealed two exported activities:

- com.hacker101.oauth.MainActivity, with an intent-filter for `oauth://login/`
- com.hacker101.oauth.Browser, with an intent-filter for `oauth://final/`

Both activities are exported because they have intent-filters and targetSdkVersion is 28. That means any other application, or adb, can start them with arbitrary data.

The manifest also set `android:usesCleartextTraffic="true"`, which allows HTTP traffic. That detail is not directly part of the exploit, but it is a sign that the application does not take transport security seriously.

Three Java classes were relevant:

- MainActivity: builds the OAuth URL and starts an external browser.
- Browser: opens a WebView, attaches a JavaScript interface called `iface`, and loads whatever URL the caller passes in.
- WebAppInterface: exposes a single method `getFlagPath()` to JavaScript.

The rest of this write-up walks through each flag and shows where the weakness lives in these three files.

---

## Flag 0 - OAuth redirect_uri manipulation

### What the code showed

MainActivity onCreate reads a query parameter called `redirect_uri` from the intent's data URI and stores it in a field:

```java
this.authRedirectUri = "oauth://final/";
try {
    Uri data = getIntent().getData();
    if (data != null && data.getQueryParameter("redirect_uri") != null) {
        this.authRedirectUri = data.getQueryParameter("redirect_uri");
    }
} catch (Exception unused) {}
```

On button click, the activity builds the OAuth URL using that value:

```java
str = "https://<ctf-host>/oauth?redirect_url="
    + URLEncoder.encode(this.authRedirectUri, ...)
    + "login&response_type=token&scope=all";
Intent intent = new Intent("android.intent.action.VIEW");
intent.setData(Uri.parse(str));
startActivity(intent);
```

So the redirect target is fully attacker-controlled. The application never validates it against a whitelist. There is no check that the URL belongs to the `oauth://final/` scheme, and no check that the host is anything in particular.

The OAuth server, in turn, trusts the `redirect_url` parameter and builds a link with the token attached. The token is placed in the URL and handed back to whoever asked.

### What I did

Since the OAuth server is reachable over HTTP and the flow is stateless, I did not need the Android app at all. I replicated the URL that MainActivity would build and sent it directly with curl:

```bash
curl -i "https://918e410b130e3880516b0d797d384d35.ctf.hacker101.com/oauth?redirect_url=http://example.com/login&response_type=token&scope=all"
```

The server responded with a page containing an anchor element:

```html
<a href="http://example.com/login?token=^FLAG^...$FLAG$">
Authorize Mobile Application
</a>
```

The token in the URL was the first flag. The server had accepted an arbitrary redirect_uri and embedded the token into it. Any attacker who controls the redirect target receives the token, and the victim's browser or the victim's app is the one that delivers it.

### Why it worked

OAuth 2.0 requires the authorization server to validate the redirect_uri against a whitelist registered for the client. If the server accepts any value, an attacker can point the redirect at a domain they control and receive the access token that was meant for the legitimate client. This is one of the oldest and most common OAuth vulnerabilities. It is listed in RFC 6749 section 3.1.2.3 as a mandatory security check.

The Android side made it worse. The application accepted the `redirect_uri` from its own intent data, which is fully attacker-controlled because MainActivity is exported. So even if the server had validated the redirect_uri, the application itself would have been tricked into using an attacker-supplied value.

### How to prevent it

- On the OAuth server, whitelist exactly the redirect_uri values registered for the client. Reject everything else before issuing a token.
- On the Android side, do not accept a redirect_uri from the intent. Hardcode the value, or read it from a trusted source.
- If the application must accept redirect URIs, validate them against a strict allowlist and use exact string matching. Substring and prefix checks are not enough.
- Do not put tokens in URLs. Use the authorization code flow with PKCE and return the code in a way that the client can verify (for example, a custom scheme with an app-level verification step).
- Set MainActivity to `android:exported="false"` if it does not need to be reachable from other applications.

---

## Flag 1 - JavaScript interface abuse in a WebView

### What the code showed

Browser onCreate reads a query parameter called `uri` from the intent data and loads it into a WebView:

```java
String queryParameter = "https://<ctf-host>/authed";
try {
    Uri data = getIntent().getData();
    if (data != null && data.getQueryParameter("uri") != null) {
        queryParameter = data.getQueryParameter("uri");
    }
} catch (Exception unused) {}
WebView webView = (WebView) findViewById(R.id.webview);
webView.setWebViewClient(new SSLTolerentWebViewClient(webView));
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new WebAppInterface(getApplicationContext()), "iface");
webView.loadUrl(queryParameter);
```

Three things matter here:

1. The URL loaded into the WebView is fully attacker-controlled via the `uri` parameter.
2. JavaScript is enabled.
3. A Java object is exposed to JavaScript under the name `iface`. That object has a method `getFlagPath()`.

The WebAppInterface class contains the method:

```java
@JavascriptInterface
public String getFlagPath() { ... }
```

The method computes a filename by running a Brainfuck interpreter over a hardcoded array. The result is the name of an HTML file that lives on the server. The file contains the second flag. The WebView is supposed to load a page that calls `iface.getFlagPath()` and then navigates to that file.

The SSLTolerentWebViewClient also overrides `onReceivedSslError` and calls `sslErrorHandler.proceed()`, which disables SSL certificate validation. That is a separate issue and not needed for this exploit, but it is worth noting.

### What I did

I did not run the app. Instead, I extracted the array from the smali code and executed the same algorithm in Python. The smali file contains the array as `fill-array-data` for `:array_0`. A short Python script read the array, applied the transformation from `getFlagPath()`, and ran a minimal Brainfuck interpreter over the result. The output was a single string:

```
48ce217fea4529a070a9d3e3c87db512b1596d413e580f7b2e1eab65f3948ab8
```

Appending `.html` gave the filename of the flag file. Fetching it from the CTF host returned the second flag:

```bash
curl "https://918e410b130e3880516b0d797d384d35.ctf.hacker101.com/48ce217fea4529a070a9d3e3c87db512b1596d413e580f7b2e1eab65f3948ab8.html"
```

If I had run the app, the same result would have been achieved by starting Browser with an `uri` parameter pointing to an attacker-controlled HTML page containing:

```html
<script>document.write(iface.getFlagPath());</script>
```

The WebView would have loaded that page, executed the JavaScript, and displayed the flag filename. Navigating to the filename would have shown the flag.

### Why it worked

WebView with `addJavascriptInterface` exposes native methods to any JavaScript running in that WebView. If the WebView can be made to load attacker-controlled content, the attacker's JavaScript can call those methods. In this app, the URL loaded into the WebView came straight from the intent, and Browser is exported, so any application could start it with an arbitrary `uri`. That is enough to take full control of the WebView content and, through `iface`, of the native methods the app exposes.

The `getFlagPath()` method itself is obfuscated with a Brainfuck interpreter to make it harder to reverse, but that is security through obscurity. Once the array is extracted, the algorithm runs in milliseconds in any language.

### How to prevent it

- Do not enable JavaScript in a WebView unless it is strictly necessary. If it is, restrict the WebView to a fixed set of URLs (for example, an allowlist of trusted hosts).
- Do not expose native objects to JavaScript with `addJavascriptInterface` unless the content loaded into the WebView is fully trusted. Even then, keep the interface minimal and audit it for dangerous methods.
- If the WebView must load URLs from an external source, validate the URL against an allowlist before calling `loadUrl`. Do not trust the `uri` parameter from the intent.
- Set Browser to `android:exported="false"` if it does not need to be reachable from other applications. If it does, verify the caller with a signature-level permission or an app-link verification step.
- Do not use `onReceivedSslError` with `proceed()`. That disables certificate validation and opens the door to man-in-the-middle attacks. Handle SSL errors by failing closed.
- Do not obfuscate security-relevant logic. Obfuscation is not a control; it only delays an attacker by minutes.

---

## Root cause analysis

Both flags come from the same design mistake: the application trusted input that it did not control.

For Flag 0, the OAuth server trusted the `redirect_url` parameter from the client, and the Android app trusted the `redirect_uri` from the intent. Either of these alone would have been enough to leak the token. Together, they made the flow trivially exploitable.

For Flag 1, the WebView trusted the `uri` parameter from the intent and loaded it as content. Because the WebView also had a JavaScript bridge to native methods, the attacker's content could call `iface.getFlagPath()` and obtain the location of the flag file. The `getFlagPath()` method was obfuscated, but obfuscation is not a security boundary.

Both flags also share a second theme: exported activities. Both MainActivity and Browser were reachable from any application on the device, and neither checked who was calling it. That is what made the intent parameters attacker-controlled in the first place.

---

## What I took away from this challenge

1. OAuth redirect_uri validation is not optional. If the server accepts any redirect_uri, the token goes wherever the attacker points it. This is a specification requirement, not a nice-to-have.

2. Exported activities are an attack surface. If an activity has an intent-filter, any app on the device can start it with arbitrary data. Any parameter the activity reads from the intent should be treated as hostile input.

3. WebView plus JavaScript plus a native bridge is a dangerous combination. The WebView is only as safe as the content it loads. If that content can be influenced by an attacker, the bridge becomes a remote code execution primitive.

4. Obfuscation is not security. The `getFlagPath()` method used a Brainfuck interpreter to hide the filename computation. It took a few minutes to reimplement in Python and run against the extracted array. The obfuscation added no real protection.

5. You do not always need the device. Both flags were solved by reading the decompiled code and replaying the logic outside of Android. Static analysis plus a curl request was enough. An emulator would have been slower.

6. The v1 to v2 pattern from BugDB applies here too. Both vulnerabilities are small, well-understood mistakes that show up in real applications every week. OAuth redirect_uri bypasses are reported on real bug bounty programs on a regular basis. WebView JavaScript bridges are a recurring source of Android vulnerabilities.

---

## References

- RFC 6749 section 3.1.2.3 - Redirect URI validation: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3
- OWASP - OAuth 2.0 Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- OWASP Top 10 - A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- Android developer docs - WebView JavaScript interface: https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)
- Android developer docs - Exported components: https://developer.android.com/guide/topics/manifest/activity-element#exported
- CWE-601: URL Redirection to Untrusted Site: https://cwe.mitre.org/data/definitions/601.html
- CWE-749: Exposed Dangerous Method or Function: https://cwe.mitre.org/data/definitions/749.html
