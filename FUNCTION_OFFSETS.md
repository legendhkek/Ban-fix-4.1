# Complete Function Offset Reference - BGMI 4.1

## libAntsVoice.so - All Exported Functions

This file contains a comprehensive list of all exported functions from libAntsVoice.so with their offsets and sizes.

**Library:** libAntsVoice.so  
**Version:** BGMI 4.1  
**Architecture:** ARM64 (AArch64)  
**Total Functions:** 552 exports  

---

## Critical Functions for Ban Fixing

### Priority Level: CRITICAL ⚠️

| Offset | Size | Function Name | Purpose |
|--------|------|---------------|---------|
| 0x89E54 | 88 | AntsVoice_Init | Initialize voice system - **Entry point for hooks** |
| 0x8A850 | 120 | AntsVoice_ApplyMessageKey | Apply authentication key - **MUST PATCH** |
| 0x8B6F8 | 88 | AntsVoice_CheckDeviceMuteState | Check device ban status - **Device bans** |
| 0x8B990 | 108 | AntsVoice_ReportPlayer | Report player to server - **Disable for protection** |

### Priority Level: HIGH 🔴

| Offset | Size | Function Name | Purpose |
|--------|------|---------------|---------|
| 0x8A0B4 | 100 | AntsVoice_JoinTeamRoom | Join team room - **Token validation** |
| 0x8A118 | 100 | AntsVoice_JoinRangeRoom | Join range room - **Token validation** |
| 0x8B8C4 | 96 | AntsVoice_SetReportBufferTime | Report buffer config - **Reporting system** |
| 0x8C6C8 | 92 | AntsVoice_EnableKeyWordsDetect | Keyword detection - **Chat monitoring** |
| 0x8C9EC | 116 | AntsVoice_SetPlayerInfoAbroad | Set player info - **Account validation** |

### Priority Level: MEDIUM 🟡

| Offset | Size | Function Name | Purpose |
|--------|------|---------------|---------|
| 0x89D34 | 80 | AntsVoice_GetInstance | Get singleton instance |
| 0x89F08 | 176 | AntsVoice_Poll | Main polling loop - **Event processing** |
| 0x8A010 | 88 | AntsVoice_Resume | Resume voice session |
| 0x8A33C | 100 | AntsVoice_QuitRoom | Quit current room |
| 0x8A4EC | 100 | AntsVoice_QuitRoom_Scenes | Quit room with scene info |
| 0x8A5A8 | 88 | AntsVoice_CloseMic | Close microphone |
| 0x8A6B0 | 100 | AntsVoice_EnableRoomMicrophone | Enable/disable room mic |
| 0x8ADE8 | 96 | AntsVoice_EnableLog | Enable logging - **Debug info** |
| 0x8B07C | 116 | AntsVoice_invoke | Generic invoke method |
| 0x8CB1C | 92 | AntsVoice_EnableReportALL | Enable all reporting |

---

## Complete Function List (Alphabetical)

### A

```
0x8D68C  92   AntsVoice_AddInfoForReport
0x8A850  120  AntsVoice_ApplyMessageKey
0x8CD74  100  AntsVoice_AuditionFileForMagicType
```

### C

```
0x8B6F8  88   AntsVoice_CheckDeviceMuteState
0x8A5A8  88   AntsVoice_CloseMic
```

### D

```
0x8BC7C  100  AntsVoice_DelAllSaveVoiceFile
0x8AACC  144  AntsVoice_DownloadRecordedFile
```

### E

```
0x8CC30  92   AntsVoice_Enable3DVoice
0x8D084  92   AntsVoice_EnableAccFilePlay
0x8B69C  92   AntsVoice_EnableBluetoothSCO
0x8CE98  96   AntsVoice_EnableDualLink
0x8CF64  92   AntsVoice_EnableEarBack
0x8C6C8  92   AntsVoice_EnableKeyWordsDetect
0x8ADE8  96   AntsVoice_EnableLog
0x8CB1C  92   AntsVoice_EnableReportALL
0x8B204  92   AntsVoice_EnableReverb
0x8A6B0  100  AntsVoice_EnableRoomMicrophone
0x8C724  116  AntsVoice_EnableTranslate
```

### G

```
0x8D4C0  88   AntsVoice_GetAccPlayTimeByMs
0x8D468  88   AntsVoice_GetAccFileTotalTimeByMs
0x89D34  80   AntsVoice_GetInstance
0x8D518  88   AntsVoice_GetRecordKaraokeTotalTime
```

### I

```
0x89E54  88   AntsVoice_Init
0x8B07C  116  AntsVoice_invoke
0x8B1A8  92   AntsVoice_IsSpeaking
```

### J

```
0x8A118  100  AntsVoice_JoinRangeRoom
0x8A0B4  100  AntsVoice_JoinTeamRoom
```

### P

```
0x89F08  176  AntsVoice_Poll
```

### Q

```
0x8A33C  100  AntsVoice_QuitRoom
0x8A4EC  100  AntsVoice_QuitRoom_Scenes
```

### R

```
0x8B990  108  AntsVoice_ReportPlayer
0x8A010  88   AntsVoice_Resume
0x8B478  88   AntsVoice_ResumeBGMPlay
0x8C30C  124  AntsVoice_RSTSSpeechToText
```

### S

```
0x8D300  92   AntsVoice_SeekTimeMsForPreview
0x8D35C  92   AntsVoice_SeekTimeMsForAcc
0x8B314  92   AntsVoice_SetBGMPath
0x8B4D0  92   AntsVoice_SetBGMVol
0x8D6E8  176  AntsVoice_SetCSOnRecordingCB
0x8DA2C  100  AntsVoice_SetDeliverData
0x8D0E0  92   AntsVoice_SetKaraokeVoiceVol
0x89EAC  92   AntsVoice_SetMode
0x8C9EC  116  AntsVoice_SetPlayerInfoAbroad
0x8C5CC  100  AntsVoice_SetPlayerVolume
0x8B8C4  96   AntsVoice_SetReportBufferTime
0x8B14C  92   AntsVoice_SetVoiceEffects
0x8C024  116  AntsVoice_SpeechFileToText
0x8BF2C  124  AntsVoice_SpeechTranslate
0x8CFC0  108  AntsVoice_StartKaraokeRecording
0x8A950  128  AntsVoice_StartRecording
0x8B3C8  88   AntsVoice_StopBGMPlay
0x8ABD4  116  AntsVoice_StopPlayFile
```

### U

```
0x8AA44  136  AntsVoice_UploadRecordedFile
```

---

## Java JNI Bridge Functions

These functions are called from Java/Kotlin code via JNI.

### Critical JNI Functions

```
0x918F4  216  Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
0x8DB34  272  Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
0x8F8E8  88   Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
0x8F888  96   Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
0x8E084  232  Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
0x91A94  100  Java_com_antssdk_ants_voice_AntsVoiceEngineHelper_[...]
```

**Note:** Full JNI function names are truncated in the symbol table. These functions bridge between Java application code and native implementation.

---

## Patching Strategies by Function

### 1. Authentication Bypass

**Target: AntsVoice_ApplyMessageKey (0x8A850)**

```arm
Original (approximate):
  0x8A850: stp x29, x30, [sp, #-16]!  // Save frame pointer and link register
  0x8A854: mov x29, sp                 // Set up frame pointer
  0x8A858: ...                         // Auth logic
  
Patched (Early Return):
  0x8A850: mov w0, #0                  // Return value 0 (success)
  0x8A854: ret                         // Return immediately
  0x8A858: nop                         // No operation
  0x8A85C: nop                         // No operation
```

**Hex Patch:**
```
Address: 0x8A850
Original: [varies based on function]
Patched:  00 00 80 D2 C0 03 5F D6 1F 20 03 D5
          (mov w0, #0; ret; nop)
```

### 2. Reporting Prevention

**Target: AntsVoice_ReportPlayer (0x8B990)**

```arm
Patched (Disable Reporting):
  0x8B990: mov w0, #-1                 // Return -1 (error/disabled)
  0x8B994: ret                         // Return immediately
  0x8B998: nop                         // Fill rest with NOPs
  ...
```

**Hex Patch:**
```
Address: 0x8B990
Patched:  FF FF 80 D2 C0 03 5F D6 1F 20 03 D5
          (mov w0, #-1; ret; nop)
```

### 3. Device Check Bypass

**Target: AntsVoice_CheckDeviceMuteState (0x8B6F8)**

```arm
Patched (Always Normal State):
  0x8B6F8: mov w0, #0                  // Return 0 (normal state)
  0x8B6FC: ret                         // Return immediately
  0x8B700: nop                         // No operation
```

**Hex Patch:**
```
Address: 0x8B6F8
Patched:  00 00 80 D2 C0 03 5F D6 1F 20 03 D5
          (mov w0, #0; ret; nop)
```

### 4. Token Validation Bypass

**Target: AntsVoice_JoinTeamRoom (0x8A0B4)**

```arm
Modified (Accept Any Token):
  0x8A0B4: stp x29, x30, [sp, #-16]!
  0x8A0B8: mov x29, sp
  0x8A0BC: mov w0, #0                  // Skip validation, return success
  0x8A0C0: ldp x29, x30, [sp], #16
  0x8A0C4: ret
```

---

## ARM64 Instruction Reference

For manual patching, common ARM64 instructions used:

| Instruction | Hex Code | Purpose |
|-------------|----------|---------|
| MOV W0, #0 | 00 00 80 D2 | Set return value to 0 |
| MOV W0, #-1 | FF FF 80 D2 | Set return value to -1 |
| RET | C0 03 5F D6 | Return from function |
| NOP | 1F 20 03 D5 | No operation |
| STP X29, X30, [SP, #-16]! | FD 7B BF A9 | Save registers |
| LDP X29, X30, [SP], #16 | FD 7B C1 A8 | Restore registers |

---

## Offset Verification Commands

Use these commands to verify offsets before patching:

```bash
# Verify function exists at offset
readelf -s libAntsVoice.so | grep "8a850"

# View disassembly at offset
objdump -d libAntsVoice.so --start-address=0x8a850 --stop-address=0x8a8d0

# Extract hex bytes at offset
hexdump -C libAntsVoice.so -s 0x8a850 -n 128

# Search for function by name
nm -D libAntsVoice.so | grep AntsVoice_ApplyMessageKey
```

---

## Memory Layout Analysis

### Code Sections (.text)

```
Start:  0x4D680
End:    0x2551A0
Size:   0x207B20 (2,128,672 bytes)

Key regions:
  0x89000 - 0x90000: Core voice functions
  0x8A000 - 0x8B000: Authentication & room joining
  0x8B000 - 0x8D000: Player interaction & reporting
  0x8D000 - 0x8E000: File & recording operations
```

### Data Sections (.rodata)

```
Start:  0x2551A0
End:    0x330E78
Size:   0xDBCD8 (900,312 bytes)

Contains:
  - String constants
  - Error messages
  - Configuration data
  - Authentication keys (encrypted)
```

---

## Function Call Chains

### Authentication Flow

```
AntsVoice_Init (0x89E54)
  └─> AntsVoice_ApplyMessageKey (0x8A850)
       └─> [Internal auth validation]
            └─> AntsVoice_JoinTeamRoom (0x8A0B4)
                 └─> [Server token check]
```

**Patch Strategy:** Intercept at ApplyMessageKey to bypass entire chain.

### Reporting Flow

```
[User reports player]
  └─> AntsVoice_ReportPlayer (0x8B990)
       └─> AntsVoice_SetReportBufferTime (0x8B8C4)
            └─> [Network transmission]
```

**Patch Strategy:** Disable ReportPlayer to prevent server notification.

### Device Check Flow

```
AntsVoice_Init (0x89E54)
  └─> AntsVoice_CheckDeviceMuteState (0x8B6F8)
       └─> [Device ID validation]
            └─> [Ban status check]
```

**Patch Strategy:** Force CheckDeviceMuteState to return "normal" status.

---

## Testing & Validation

### Pre-Patch Verification

```bash
# 1. Backup original
cp libAntsVoice.so libAntsVoice.so.backup

# 2. Calculate original checksum
md5sum libAntsVoice.so > original.md5

# 3. Verify target offset
readelf -s libAntsVoice.so | grep "AntsVoice_ApplyMessageKey"
```

### Post-Patch Verification

```bash
# 1. Verify patch applied
hexdump -C libAntsVoice.so -s 0x8a850 -n 16

# 2. Check file size unchanged
ls -l libAntsVoice.so

# 3. Test in controlled environment
# (Use test account, monitor behavior)
```

---

## Advanced Techniques

### 1. Function Hooking (Frida)

```javascript
// Hook AntsVoice_ApplyMessageKey
Interceptor.attach(Module.findExportByName("libAntsVoice.so", 
  "AntsVoice_ApplyMessageKey"), {
  onEnter: function(args) {
    console.log("ApplyMessageKey called");
    console.log("Arg0: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("Returning: " + retval);
    retval.replace(0); // Force success
  }
});
```

### 2. Memory Searching (Game Guardian)

```
Search Type: Dword (4 bytes)
Search Value: Ban status flag
Range: Anonymous memory regions

Modify to: 0 (unbanned status)
Freeze: Yes
```

### 3. Dynamic Analysis

```bash
# Attach debugger
adb forward tcp:5039 tcp:5039
gdbserver :5039 --attach $(pidof com.pubg.imobile)

# Set breakpoints
break *0x7XXXXXXX8A850  # Adjust base address
continue
```

---

## Compatibility Notes

### BGMI Version 4.1.x

- ✅ All offsets verified
- ✅ Functions present
- ✅ Symbol names match
- ⚠️  May have minor sub-version differences

### Related Versions

| Version | Status | Notes |
|---------|--------|-------|
| 4.0.x | Partial | Similar structure, offsets differ |
| 4.2.x | Unknown | Not analyzed yet |
| 3.x | Incompatible | Complete rewrite |

---

## Security Warnings

### Detection Risk Factors

1. **Modified APK Signature**
   - Risk: High
   - Mitigation: Use signature bypass (Xposed, Magisk)

2. **Memory Checksums**
   - Risk: Medium
   - Mitigation: Hook checksum functions

3. **Behavioral Analysis**
   - Risk: Medium
   - Mitigation: Randomize timing, use proxies

4. **Server-Side Validation**
   - Risk: High
   - Mitigation: Limited options, complex bypass needed

---

## Appendix: Complete Symbol Dump

For the complete symbol table with all 552 functions, use:

```bash
readelf -s libAntsVoice.so > symbols_complete.txt
```

For functions only:

```bash
readelf -s libAntsVoice.so | grep FUNC | grep GLOBAL > functions_only.txt
```

---

## libUE4.so - Key Functions (NEW!)

**Library:** libUE4.so  
**Version:** BGMI 4.1  
**Architecture:** ARM64 (AArch64)  
**Total Functions:** ~458,000+ (decompiled)  
**File Size:** 95 MB (decompiled source)

### Critical Anti-Cheat Functions

⚠️ **Note:** libUE4.so offsets require extraction of the original binary from APK. The decompiled source uses function names like `sub_XXXXXXX` which correspond to offsets `0xXXXXXXX`.

#### Priority Level: CRITICAL ⚠️

| Component | Purpose | Ban Impact |
|-----------|---------|------------|
| **PlayerAntiCheatManager** | Central anti-cheat coordination | CRITICAL |
| **WeaponAntiCheatComp** | Weapon validation system | CRITICAL |
| **PlayerSecurityInfoCollector** | Player behavior monitoring | HIGH |

#### Key Security Components

**1. WeaponAntiCheatComp Functions:**
- `Clear_AntiCheatOnSwapOwner` - Clears anti-cheat state on weapon change
- `VerifyServerShootProjectileBullet` - **SERVER-SIDE** bullet validation (CANNOT BYPASS)

**2. PlayerAntiCheatManager:**
- Central coordination of all anti-cheat systems
- Ban decision enforcement
- Communication with external anti-cheat (libanogs.so)

**3. PlayerSecurityInfoCollector:**
- `GetRecordAIBotMap` - Records AI bot interactions (aimbot detection)
- Collects player behavior data
- Evidence collection for permanent bans

**4. TimeWatchDogComponent:**
- Time synchronization validation
- Speed hack detection
- Client-server time comparison

**5. Vehicle Anti-Cheat (VacAcceleration / VacTimeSpeed):**
- Vehicle physics validation
- Speed limit enforcement
- Acceleration monitoring

**6. SecurityLogWeaponCollector:**
- `[SecurityLog OnCharacterWeaponShootHit]` - Weapon hit event logging
- Server-side analysis feed

### JNI Interface Functions

#### Epic Games UE4 GameActivity

| Function | Parameters | Purpose | Ban Impact |
|----------|-----------|---------|------------|
| `Java_com_epicgames_ue4_GameActivity_nativeSetChipSet` | Device info | Device fingerprinting | LOW |
| `Java_com_epicgames_ue4_GameActivity_nativeSetSensorAvailability` | Sensor flags | Device fingerprinting | LOW |
| `JNI_OnLoad` | JavaVM | Initialize JNI | CRITICAL |

### Detection Mechanisms

**Real-Time Monitoring:**
1. Weapon fire rate violations
2. Recoil pattern anomalies  
3. Movement speed abnormalities
4. Vehicle physics violations
5. Bullet trajectory manipulation (server-verified)
6. Aim assistance patterns
7. Time manipulation

### Extraction Instructions

To get exact offsets for libUE4.so:

```bash
# Extract from APK
unzip BGMI_4.1.apk
cd lib/arm64-v8a/

# Analyze with readelf
readelf -s libUE4.so | grep -i "security\|anticheat"

# Or use Ghidra/IDA Pro
# 1. Load libUE4.so
# 2. Search for strings: "PlayerAntiCheat", "WeaponAntiCheat", "Security"
# 3. Cross-reference with decompiled source (libUE4.so.c)
```

### Important Notes

🚫 **SERVER-SIDE VALIDATION:**
The following CANNOT be bypassed by modifying libUE4.so:
- VerifyServerShootProjectileBullet (bullet trajectory validation)
- Server time synchronization
- Physics validation

⚠️ **Decompiled Source:**
- libUE4.so.c provides function structure but not exact offsets
- Original binary analysis required for precise offsets
- Use string references to locate functions

**For detailed analysis:** See [libUE4_COMPLETE_ANALYSIS.txt](libUE4_COMPLETE_ANALYSIS.txt)

---

**Document Version:** 1.1  
**Last Updated:** 2025-11-18  
**Game Version:** BGMI 4.1  
**Libraries:** libAntsVoice.so, libUE4.so  
**Status:** Research Complete ✅
