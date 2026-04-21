---
name: mobile-security-expert
description: "Guides mobile app vulnerability hunting based on 100+ real HackerOne reports — covers Android component exploits, iOS URL scheme attacks, 2FA bypass, deeplink CSRF, WebView info leaks, and API key exposure. Use when performing mobile pentests, bug bounty hunting, code auditing Android/iOS apps, or studying exploit techniques from disclosed reports."
user-invocable: true
triggers:
  - "mobile security"
  - "android vulnerability"
  - "ios vulnerability"
  - "bug bounty mobile"
  - "mobile pentest"
  - "HackerOne mobile"
  - "漏洞挖掘"
  - "移动安全"
  - "代码审计"
  - "reverse engineering app"
  - "deeplink attack"
  - "URL scheme exploit"
  - "2FA bypass"
  - "WebView security"
  - "android exploit"
  - "ios exploit"
---

# Mobile Security Vulnerability Research — HackerOne Knowledge Base

## Workflow

### 1. Identify target scope

- Determine platform: Android, iOS, or cross-platform
- Classify vulnerability type: component security, business logic, data storage, API security, authentication bypass, deeplink/URL scheme

### 2. Retrieve matching cases from knowledge base

- **Android vulnerabilities**: Read [android.md](android.md) — 100+ cases covering exported Activity exploits, Intent hijacking, insecure data storage, 2FA logic flaws, API key exposure, WebView misconfigurations
- **iOS vulnerabilities**: Read [IOS.md](IOS.md) — 100+ cases covering URL Scheme handling, Deep Link CSRF, data protection bypass, WebView info leaks, API security flaws

Each case contains three sections:
1. **Mining technique** — step-by-step discovery process with tool commands
2. **Technical details** — attack flow, payload construction, exploitation specifics
3. **Vulnerable code patterns** — code examples showing insecure vs. secure implementations

**If no matching case found**: Apply general vulnerability class heuristics, note the gap, and recommend the closest related case as a starting point.

### 3. Deliver actionable guidance

- Provide concrete commands the researcher can execute immediately
- Include tool-specific instructions (Drozer, Frida, Burp Suite, objection)
- Show vulnerable vs. secure code patterns side-by-side when analyzing user code
- Link to original HackerOne report for full context

**Validation checkpoint**: Confirm the guidance matches the user's target platform and app context before proceeding to deeper analysis.

### 4. Iterate on failed exploitation

If an exploit does not reproduce or initial analysis finds no match:
- Verify the target app version matches the case — patches may have fixed the vulnerability
- Check for additional protections (certificate pinning, runtime integrity checks, WAF rules)
- Try alternative attack vectors from related cases in the knowledge base
- If no matching case exists, apply general vulnerability class heuristics and document the gap

## Quick reference

See [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for Android security testing checklists, critical code patterns, and essential testing workflow.

## Concrete examples

### Example 1: Enumerate exported Android Activities

**Goal**: Find authentication bypass via exported Activity components

```bash
# List exported activities with Drozer
run app.activity.info -a com.target.app

# Launch a sensitive activity directly (bypassing auth)
run app.activity.start --component com.target.app com.target.app.admin.DashboardActivity

# Check AndroidManifest.xml for exported="true" on sensitive activities
aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 "activity.*Dashboard"
```

### Example 2: Hook iOS URL Scheme handler with Frida

**Goal**: Intercept and analyze URL Scheme processing for injection/CSRF

```javascript
// Frida script — hook openURL handler in AppDelegate
Interceptor.attach(ObjC.classes.AppDelegate['- application:openURL:options:'].implementation, {
  onEnter: function(args) {
    var url = new ObjC.Object(args[3]);
    console.log('[URL Scheme] Received: ' + url.absoluteString());
  }
});
```

### Example 3: Test 2FA rate limiting with Burp Suite

**Goal**: Discover missing rate limits on SMS verification endpoints

```
# Burp Intruder setup:
# 1. Intercept POST /api/v1/verify-sms
# 2. Set payload position on "code" parameter
# 3. Use numeric payload 000000-999999
# 4. Monitor for 200 OK responses — indicates no rate limiting
# 5. Check if phone number binding lacks authorization (IDOR)
```

## Important notes

- **Selective retrieval**: Read only relevant sections of android.md/IOS.md based on the query — avoid loading entire documents
- **Real cases**: Every case traces back to a public HackerOne report with original links
