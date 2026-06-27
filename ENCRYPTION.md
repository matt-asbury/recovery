# Encrypted volumes

Recovery **cannot break FileVault or APFS encryption**. Encrypted bytes on disk look like random noise to a file carver. This document explains what the tool detects and the workflow that actually works.

## What Recovery detects

When listing live Mac volumes, Recovery reads encryption state from `diskutil`:

| Status | Meaning |
| ------ | ------- |
| **none** | Not encrypted — deep, hybrid, and quick scans behave normally |
| **locked** | Encrypted and locked — scanning is blocked until you unlock |
| **unlocked** | Encrypted but unlocked in this session — filesystem scans work; raw carving does not |
| **unknown** | Disk images and some devices — encryption cannot be confirmed |

The UI shows a banner when you select an encrypted volume. The CLI prints encryption status with `--list` and before scanning.

## What works (and what does not)

| Scan mode | Unencrypted | Encrypted + mounted | Encrypted + locked |
| --------- | ----------- | ------------------- | ------------------ |
| Quick | Yes | Yes (reads files via mount) | No — unlock first |
| Hybrid | Yes | Yes (filesystem walk; carving skipped) | No — unlock first |
| Deep | Yes | **No** — reads ciphertext | No — unlock first |

**Important:** Even when an encrypted volume is unlocked, **deep scan and carving read encrypted blocks from the raw device**. Only **Quick** and **Hybrid** (filesystem walk) access decrypted file content through the mounted volume.

## Recommended workflow

### 1. Unlock the volume

Use **Disk Utility** (File → Unlock), or from Terminal:

```bash
# APFS / modern FileVault
diskutil apfs unlockVolume /dev/diskXsY

# Older Core Storage volumes
diskutil cs unlockVolume /dev/diskXsY
```

### 2. Mount the volume

If it does not mount automatically:

```bash
diskutil mount /dev/diskXsY
```

### 3. Scan with Quick or Hybrid

- **Quick** — existing files on the mounted volume (original paths and names)
- **Hybrid** — same filesystem walk, plus an attempt to carve deleted data from unallocated space (carving is **skipped** on encrypted volumes because it cannot read decrypted bytes from raw blocks)

### 4. Recover to another drive

Select files and recover to a **different** destination disk, as usual.

## Disk images from encrypted Macs

A raw `dd` image of an encrypted APFS volume still contains **encrypted** data. Recovery marks disk images as **encryption unknown** and allows carving, but results will be useless unless the image was produced from decrypted/plain media.

Better options:

1. Unlock and mount the source Mac volume, then use **Quick/Hybrid** scan directly
2. Copy files out with Finder or `cp -a` while mounted
3. Use Apple tools to create a decrypted backup before imaging (outside Recovery’s scope)

## What Recovery will not do

- Decrypt volumes without your password or recovery key
- Integrate with institutional recovery keys or keychains
- Repair FileVault or APFS crypto metadata
- Guarantee recovery of deleted files on encrypted APFS (requires filesystem-level tools beyond carving)

For critical data on encrypted failing drives: **stop using the disk**, unlock if possible, copy important files immediately via the mounted filesystem, then image if needed.

## See also

- [README.md](README.md) — limitations overview
- [SECURITY.md](SECURITY.md) — reporting security issues
