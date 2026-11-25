---
name: Missed attack (false negative)
about: A ClickFix-style command pasteproof didn't flag
labels: detection
---
**Defanged command** (replace real domains with `.example`, real IPs with `203.0.113.x`; never post live URLs):

```
```

**Expected verdict:** caution / danger

**Where it came from** (blog post, report, your own analysis, no live links to malware):

**`pasteproof why -- '<command>'` output:**
