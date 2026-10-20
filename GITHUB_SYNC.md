# Sync to GitHub

Run these commands from the Chrovia repository root.

Add the remote once per local clone:

```bash
git remote add tcp-fingerprint git@github.com:ChroviaHQ/tcp-fingerprint.git
```

After committing changes to `tcp-fingerprint/`, push them to the standalone repository:

```bash
git subtree push --prefix=tcp-fingerprint tcp-fingerprint main
```
