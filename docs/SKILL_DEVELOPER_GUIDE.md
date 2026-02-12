# Skill Developer Best Practices

A guide to building skills that are auditable, trustworthy, and easy for users and runtimes to verify. These practices align with what security auditors look for when assessing skills.

---

## 1. Document your purpose clearly

**Include a SKILL.md** — and make it describe what the skill actually does.

- **Do:** State the skill's purpose in plain language. "This skill fetches arXiv papers by ID and summarizes them."
- **Don't:** Claim capabilities you don't have. If your code doesn't deploy to Kubernetes, don't say it does.

Auditing tools cross-reference your description against the code. Mismatches erode trust.

---

## 2. Keep instructions aligned with reality

**Only reference files and commands that exist.**

- **Do:** Refer to scripts, config files, and binaries that are in the package or clearly documented.
- **Don't:** Instruct users to "run `scripts/train.py`" if that file doesn't exist.

Ghost references suggest copy-pasted docs or an incomplete skill.

---

## 3. Declare your credentials

**If the skill reads API keys or environment variables, say so.**

- **Do:** List every required env var in SKILL.md (e.g., `PEXELS_API_KEY`, `DATABASE_URL`).
- **Don't:** Access credentials in code without documenting them.

Users need to know exactly what secrets the skill will read so they can scope permissions.

---

## 4. Declare your external tools

**If the skill invokes external binaries (curl, ffmpeg, python3, etc.), declare them.**

Put them in your skill config or SKILL.md metadata:

**skill.json:**
```json
{
  "openclaw": {
    "requires": {
      "bins": ["curl", "jq", "ffmpeg"]
    }
  }
}
```

**SKILL.md frontmatter:**
```yaml
---
metadata:
  openclaw:
    requires:
      bins: [curl, jq, ffmpeg]
---
```

- **Do:** List every binary your code (or scripts it calls) uses.
- **Don't:** Omit tools because they're "obvious" — runtimes and auditors use declarations to verify consistency.

Today only ~15% of skills declare tools. Adopting this helps reviewers and users know what to expect.

---

## 5. Be explicit about install and execution

**Document how the skill is installed and what runs at install time.**

- **Do:** Use `pyproject.toml` or a clear install script. Explain what executes during setup.
- **Don't:** Rely on undocumented `setup.py` or scripts that run arbitrary code without explanation.

Install-time execution is high-risk because it runs before users have a chance to audit runtime behavior.

---

## 6. Be explicit about persistence and privilege

**Clarify when and how the skill runs.**

- **always: true** — The skill runs on every agent invocation. Use sparingly and document why.
- **model-invocable** — The agent can invoke the skill without explicit user request. Default is true.
- **force_install** — Installs system-wide instead of per-workspace.

If your skill has system access or runs subprocesses *and* is always-on, auditors will flag it as high-stakes. Make sure that's intentional.

---

## 7. Audit yourself before publishing

**Cross-check your claims against your code.**

Before release, verify that:

- SKILL.md claims match what the code actually does  
- Referenced files and commands exist  
- Declared credentials and tools line up with actual usage  
- Install and persistence settings are intentional  

Fix any mismatches before users or auditors find them.

---

## Quick checklist before release

- [ ] SKILL.md exists and describes what the skill actually does
- [ ] Instructions reference only files that exist
- [ ] Required API keys / env vars are listed
- [ ] External binaries (curl, ffmpeg, etc.) are declared in `requires.bins`
- [ ] Install process is documented and minimal
- [ ] Persistence settings (always-on, force-install) are intentional and documented
- [ ] Self-audit passes or explains remaining findings

---

## Further reading

- [CHANGELOG.md](CHANGELOG.md) — Recent security and scanner improvements
- [ROADMAP.md](ROADMAP.md) — Deferred enhancements and future plans

---

*Skills that follow these practices are easier to trust and easier to adopt.*
