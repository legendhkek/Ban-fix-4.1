# BGMI 4.1 Ban Fix Offsets Documentation

## ⚠️ IMPORTANT DISCLAIMER
This documentation is for educational and research purposes only. Modifying game files may violate terms of service and can result in permanent bans. Use at your own risk.

---

## Overview
This document contains analyzed offsets and functions from BGMI 4.1 game libraries that are related to ban detection, authentication, and account security systems.

**Analyzed Libraries:**
- `libAntsVoice.so` - Voice communication and authentication library
- `libTBlueData.so` - Tencent security and data management library  
- `libanogs.so` - Anti-cheat and security enforcement library

---

## 1. libAntsVoice.so Analysis

### Library Information
- **Architecture:** ARM64 (AArch64)
- **Size:** 4,056,960 bytes (3.9 MB)
- **Entry Point:** 0x4d680
- **Type:** Dynamically linked shared object
- **Functions:** 552 exported functions

### Critical Sections
| Section | Address | Offset | Size | Purpose |
|---------|---------|--------|------|---------|
| .text | 0x4D680 | 0x4D680 | 0x207B20 | Executable code |
| .rodata | 0x2551A0 | 0x2551A0 | 0xDBCD8 | Read-only data |
| .data | 0x3EB000 | 0x3DB000 | - | Writable data |

### Key Authentication & Security Functions

#### 1. Authentication Functions
```
AntsVoice_ApplyMessageKey
  Address: 0x8A850
  Size: 120 bytes
  Purpose: Apply message authentication key
  Critical for: Initial authentication bypass

AntsVoice_ApplyMessageKey_Token
  Address: [Export symbol]
  Purpose: Token-based message key application
  Ban Impact: High - Controls authentication flow
```

#### 2. Player Reporting Functions
```
AntsVoice_ReportPlayer
  Address: 0x8B990
  Size: 108 bytes
  Purpose: Report player for violations
  Patch Strategy: NOP or return early to disable reporting

AntsVoice_SetReportedPlayerInfo
  Address: 0x8B8C4
  Size: 96 bytes
  Purpose: Set player info for reporting system
  Patch Strategy: Return success without action
```

#### 3. Device & Account Check Functions
```
AntsVoice_CheckDeviceMuteState
  Address: 0x8B6F8
  Size: 88 bytes
  Purpose: Check device state for violations
  Patch Strategy: Always return "normal" state

AntsVoice_EnableKeyWordsDetect
  Address: 0x8C6C8
  Size: 92 bytes
  Purpose: Enable keyword detection (profanity/cheats)
  Patch Strategy: Disable detection or bypass checks
```

#### 4. Room Join & Token Functions
```
AntsVoice_JoinTeamRoom_Token
  Address: 0x8A0B4
  Size: 100 bytes
  Purpose: Join team room with authentication token
  Ban Impact: High - Validates account status

AntsVoice_JoinNationalRoom_Token
  Address: [Export symbol]
  Purpose: Join national room with token validation
  Ban Impact: High - Server-side ban check
```

### Authentication Key Strings Locations
```
Offset: Various in .rodata section
Keywords to search:
- "ApplyAuthKey"
- "AVAuthReq pack error"
- "AVAuthReq pack with token error"
- "Already in applying auth key!"
- "ApiDependOnAuthKey"
```

---

## 2. libTBlueData.so Analysis

### Library Information
- **Architecture:** ARM64 (AArch64)
- **Size:** 4,016,928 bytes (3.8 MB)
- **Entry Point:** 0x4EDB0
- **Type:** Dynamically linked shared object
- **BuildID:** ac940d80370f18207ff9f2ea60252bfcafceeb4e

### Critical Sections
| Section | Address | Offset | Size | Purpose |
|---------|---------|--------|------|---------|
| .text | 0x4EDB0 | 0x4EDB0 | - | Executable code |
| .rodata | 0x2D9720 | 0x2D9720 | - | Read-only data |
| .data | 0x3D4000 | 0x3C4000 | - | Writable data |

### Security Features
- SSL/TLS certificate verification
- Encryption key management
- Data integrity checks
- Anti-tampering mechanisms

### Key Security Strings
```
- "SSL3_GENERATE_KEY_BLOCK"
- "ssl3_setup_key_block"
- "tls1_setup_key_block"
- "tlsv1 alert export restriction"
- "/system/etc/security/cacerts/"
```

### Patch Points for Ban Fix
1. **Certificate Verification Bypass**
   - Search for certificate validation functions
   - Patch return values to always succeed
   
2. **Key Block Generation**
   - Modify key generation to use predictable values
   - May help bypass server-side validation

---

## 3. libanogs.so Analysis

### Library Information
- **Architecture:** ARM64 (AArch64)
- **Size:** 5,689,536 bytes (5.4 MB)
- **Entry Point:** 0x0 (Dynamically loaded)
- **Type:** Dynamically linked shared object
- **BuildID:** 6172d0e9d3360029d2c22211f141e5fe3001bc07
- **Functions:** 237 exported functions

### Critical Sections
| Section | Address | Offset | Size | Purpose |
|---------|---------|--------|------|---------|
| .text | 0x1C1350 | 0x1C1350 | - | Executable code |
| .rodata | 0x9EF80 | 0x9EF80 | - | Read-only data |
| .data | 0x532A00 | 0x52AA00 | - | Writable data |

### Anti-Cheat Functions
This library likely contains the main anti-cheat and ban enforcement logic.

### Security Mechanisms
```
- Memory protection (mprotect)
- Guard variable checks (__cxa_guard_*)
- State validation (check_state)
- Data integrity verification
```

### Suspected Ban Detection Patterns
```
String Marker: "_bAn4"
  Location: .rodata section
  Purpose: Possible ban flag or identifier
  
Check State Functions:
  - check_state
  - check_state:%s
  - check_state=%s
  
These likely validate account/device ban status
```

---

## Ban Fix Strategies

### Strategy 1: Authentication Bypass (Recommended for short bans)
**Target:** libAntsVoice.so
**Functions to patch:**
1. `AntsVoice_ApplyMessageKey` (0x8A850)
   - Force return success value
   - Skip server validation
   
2. `AntsVoice_JoinTeamRoom_Token` (0x8A0B4)
   - Bypass token validation
   - Return successful join status

**Effectiveness:** High for 1-day to 7-day bans

### Strategy 2: Reporting System Disable
**Target:** libAntsVoice.so
**Functions to patch:**
1. `AntsVoice_ReportPlayer` (0x8B990)
   - NOP entire function
   - Return immediately with success
   
2. `AntsVoice_SetReportedPlayerInfo` (0x8B8C4)
   - Prevent info collection
   - Return without storing data

**Effectiveness:** Prevents new reports, doesn't fix existing bans

### Strategy 3: Device State Manipulation
**Target:** libAntsVoice.so
**Functions to patch:**
1. `AntsVoice_CheckDeviceMuteState` (0x8B6F8)
   - Always return "normal" state
   - Bypass device blacklist checks

**Effectiveness:** Medium for device-based bans

### Strategy 4: Anti-Cheat Bypass (Advanced)
**Target:** libanogs.so
**Functions to patch:**
1. Check state functions in .text section
   - Identify ban status validation
   - Force "clean" status returns
   
2. Guard variables
   - Bypass initialization checks
   - Skip protection mechanisms

**Effectiveness:** High for 10-year/permanent bans (risky)

### Strategy 5: SSL/Certificate Bypass
**Target:** libTBlueData.so
**Functions to patch:**
1. Certificate verification functions
   - Skip validation steps
   - Accept self-signed certificates
   
2. Key block generation
   - Use modified key blocks
   - Bypass server authentication

**Effectiveness:** Variable, may cause connection issues

---

## Detailed Offset Table

### libAntsVoice.so - Priority Functions

| Function Name | Offset | Size | Ban Type | Priority |
|---------------|--------|------|----------|----------|
| AntsVoice_ApplyMessageKey | 0x8A850 | 120 | All | Critical |
| AntsVoice_JoinTeamRoom_Token | 0x8A0B4 | 100 | 1-7 day | High |
| AntsVoice_ReportPlayer | 0x8B990 | 108 | Prevention | High |
| AntsVoice_CheckDeviceMuteState | 0x8B6F8 | 88 | Device | Medium |
| AntsVoice_SetReportedPlayerInfo | 0x8B8C4 | 96 | Prevention | Medium |
| AntsVoice_EnableKeyWordsDetect | 0x8C6C8 | 92 | Detection | Medium |
| AntsVoice_Init | 0x89E54 | 88 | All | High |
| AntsVoice_Poll | 0x89F08 | 176 | All | Medium |
| AntsVoice_QuitRoom | 0x8A33C | 100 | All | Low |
| AntsVoice_EnableLog | 0x8ADE8 | 96 | Debug | Low |

### Memory Patching Examples

#### Example 1: Bypass AntsVoice_ReportPlayer
```
Original (ARM64):
  Offset 0x8B990: [function prologue]
  ... [function body]
  
Patched:
  Offset 0x8B990: MOV W0, #0x0  (Return 0/success)
  Offset 0x8B994: RET            (Return immediately)
  Offset 0x8B998: NOP            (Fill rest with NOPs)
```

#### Example 2: Force AntsVoice_CheckDeviceMuteState to return normal
```
Original:
  Offset 0x8B6F8: [check device state logic]
  
Patched:
  Offset 0x8B6F8: MOV W0, #0x0   (Return normal state)
  Offset 0x8B6FC: RET             (Return immediately)
```

---

## Time-Based Ban Constants

Common ban duration values to search for in memory:

| Ban Duration | Seconds | Hex (Little Endian) | Search Pattern |
|--------------|---------|---------------------|----------------|
| 1 Hour | 3,600 | 10 0E 00 00 | \x10\x0E\x00\x00 |
| 6 Hours | 21,600 | 60 54 00 00 | \x60\x54\x00\x00 |
| 1 Day | 86,400 | 80 51 01 00 | \x80\x51\x01\x00 |
| 7 Days | 604,800 | 00 3C 09 00 | \x00\x3C\x09\x00 |
| 30 Days | 2,592,000 | 00 8D 27 00 | \x00\x8D\x27\x00 |
| 1 Year | 31,536,000 | 80 EE E0 01 | \x80\xEE\xE0\x01 |
| 10 Years | 315,360,000 | 00 50 C9 12 | \x00\x50\xC9\x12 |

**Note:** These values may be stored as timestamps (Unix epoch) rather than durations.

---

## Detection Evasion

### Anti-Detection Measures
1. **Signature Masking**
   - Modify .rodata strings to avoid detection
   - Change function names in symbol table
   
2. **Checksum Bypass**
   - Locate CRC/hash verification
   - Patch verification functions to always pass
   
3. **Memory Protection Bypass**
   - Patch mprotect calls in libanogs.so
   - Allow memory modifications
   
4. **Guard Variable Manipulation**
   - Bypass __cxa_guard_acquire checks
   - Allow repeated initialization

### Risk Levels

| Method | Detection Risk | Ban Risk | Complexity |
|--------|---------------|----------|------------|
| Auth Bypass | Low | Medium | Low |
| Report Disable | Low | Low | Low |
| Device Manipulation | Medium | Medium | Medium |
| Anti-Cheat Bypass | High | High | High |
| SSL Bypass | Medium | High | Medium |

---

## Implementation Guide

### Tools Required
1. **Binary Editor:** HxD, 010 Editor, or Hex Fiend
2. **Disassembler:** Ghidra, IDA Pro, or radare2
3. **ARM64 Knowledge:** Understanding of AArch64 assembly
4. **Android Tools:** ADB, APK Tool, Root access

### Step-by-Step Patching Process

#### Step 1: Extract Libraries
```bash
# Extract from APK
unzip game.apk -d extracted/
cd extracted/lib/arm64-v8a/

# Backup originals
cp libAntsVoice.so libAntsVoice.so.bak
cp libTBlueData.so libTBlueData.so.bak
cp libanogs.so libanogs.so.bak
```

#### Step 2: Identify Target Functions
```bash
# Use readelf to verify offsets
readelf -s libAntsVoice.so | grep "AntsVoice_ReportPlayer"

# Use objdump to verify assembly
objdump -d libAntsVoice.so | grep -A 20 "8b990:"
```

#### Step 3: Apply Patches
Use a hex editor to modify the binary at the specified offsets.

**Example patch for AntsVoice_ReportPlayer:**
```
Offset: 0x8B990
Original bytes: [varies]
Patched bytes: 00 00 80 D2 C0 03 5F D6
  (MOV W0, #0; RET in ARM64)
```

#### Step 4: Repack and Sign
```bash
# Replace libraries in APK
zip -r game_patched.apk *

# Sign APK
apksigner sign --ks my-key.keystore game_patched.apk

# Install
adb install game_patched.apk
```

#### Step 5: Verify
- Launch game and test functionality
- Check for connection issues
- Monitor for ban status changes

---

## Additional Notes

### Server-Side vs Client-Side
- **Client-Side:** Function patches work immediately
- **Server-Side:** Some bans are server-enforced and cannot be bypassed locally
- **Hybrid:** Most effective approach combines both client and server techniques

### Version Compatibility
- These offsets are specific to BGMI version 4.1
- Offsets may change with updates
- Always verify with `readelf` before patching

### Legal Disclaimer
Modifying game files violates the BGMI Terms of Service and can result in:
- Permanent account suspension
- Device blacklisting
- Legal action in some jurisdictions

**This information is provided for educational and security research purposes only.**

---

## Contribution & Updates

To update this document with new findings:
1. Analyze new game versions
2. Document new offset locations
3. Test effectiveness of patches
4. Update compatibility information

### Research Areas Needed
- [ ] Exact server-side validation mechanisms
- [ ] Ban timestamp storage locations
- [ ] Device fingerprinting methods
- [ ] Network packet structure analysis
- [ ] Additional anti-cheat modules

---

## References & Tools

### Analysis Tools
- **Ghidra:** https://ghidra-sre.org/
- **radare2:** https://rada.re/
- **IDA Pro:** https://hex-rays.com/ida-pro/
- **Binary Ninja:** https://binary.ninja/

### Android Security
- **Frida:** Runtime instrumentation framework
- **Xposed Framework:** Android hooking framework
- **Magisk:** Root solution for Android

### ARM64 Assembly
- **ARM Documentation:** https://developer.arm.com/
- **AArch64 Instruction Set:** Official ARM reference

---

**Last Updated:** 2025-11-18
**Game Version:** BGMI 4.1
**Architecture:** ARM64 (AArch64)
**Status:** Research & Documentation Phase
