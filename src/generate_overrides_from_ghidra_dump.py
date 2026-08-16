#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, sys, json
from pathlib import Path

CC = ["__vectorcall", "__thiscall", "__fastcall", "__stdcall", "__cdecl"]
SKIP = {"__SEH_prolog", "__SEH_epilog", "_except_handler3", "__security_check_cookie"}
T_AL = {
    "undefined":"void", "undefined1":"unsigned char", "undefined2":"unsigned short", 
    "undefined4":"unsigned int", "undefined8":"unsigned long long", "byte":"unsigned char", 
    "uint":"unsigned int", "ulong":"unsigned long", "ushort":"unsigned short"
}
STR_F = "strcmp strncmp stricmp _stricmp strlen strcpy strncpy strcat strncat lstrcmp wsprintf sprintf CreateFileA CreateFileW LoadLibraryA GetProcAddress".split()
MEM_F = "memcpy memmove memset memcmp".split()
FWD = {k: f"msvcrt.{k}" for k in "strcmp _strcmp strncmp _strncmp strlen _strlen strcpy _strcpy strncpy _strncpy strcat _strcat strncat _strncat memcpy _memcpy memmove _memmove memset _memset memcmp _memcmp malloc _malloc free _free realloc _realloc atoi _atoi atol _atol qsort _qsort bsearch _bsearch".split()}
FWD.update({"stricmp": "msvcrt._stricmp", "_stricmp": "msvcrt._stricmp"})

def norm_t(t):
    t = re.sub(r"\s+", " ", t or "void").replace(" *", "*").strip()
    for s, d in T_AL.items():
        t = re.sub(rf"\b{s}\b", d, t)
    return t

def extract_funcs(txt):
    res = []
    # Hardened regex to handle calling conventions gracefully in group 1
    for m in re.finditer(r'^([\w\s\*:]+?)\b([A-Za-z_]\w*)\s*\(([^)]*)\)[^{]*\{', txt, re.M):
        ret, name, args, start = m.group(1).strip(), m.group(2), m.group(3), m.end() - 1
        if name in SKIP or name in ("if", "while", "for", "switch", "return"):
            continue
        d, end = 0, start
        for i in range(start, len(txt)):
            if txt[i] == '{': d += 1
            elif txt[i] == '}': d -= 1
            if d == 0:
                end = i; break
        res.append((ret, name, args, txt[start+1:end]))
    return res

def infer(ret, name, args, body):
    if name in FWD:
        return {"kind": "forward_export", "function_name": name, "forward_target": FWD[name]}
    
    # Extract calling convention cleanly before formatting return type
    cc = "__cdecl"
    for c in CC:
        if c in ret:
            cc = c
            ret = ret.replace(c, "")
            break
            
    ret = norm_t(ret)
    if re.search(r"\breturn\s+(0xffffffff|-1)\s*;", body) and ret == "unsigned int":
        ret = "int"
        
    ps = []
    for i, p in enumerate(re.split(r',\s*(?![^()]*\))', args)):
        if not p.strip() or p == "void": continue
        pm = re.match(r"^(.*?)([A-Za-z_]\w*)$", p.strip())
        t, n = (pm.groups() if pm else (p, f"param_{i+1}"))
        n, en = n.strip(), re.escape(n.strip())
        pt, conf = norm_t(t), "high" if "undefined" not in t else "low"
        
        ptr = re.search(rf"\*\s*{en}\s*=|{en}\s*\[|{en}\s*[\+\-]", body)
        # Tightened function mapping bounds using lookbehinds/lookaheads to prevent string matching collisions
        str_use = re.search(rf"\b(?:{'|'.join(STR_F)})\s*\([^)]*\b{en}\b[^)]*\)|\(char\s*\*\)\s*{en}", body)
        mem_use = re.search(rf"\b(?:{'|'.join(MEM_F)})\s*\([^)]*\b{en}\b[^)]*\)", body)
        
        is_unk = "undefined" in t or pt in ("unsigned int", "unsigned long long", "void")
        if ptr and str_use:
            pt, conf = ("char*" if "=" in ptr.group(0) else "const char*"), "high"
        elif ptr:
            pt, conf = (pt if pt.endswith("*") else ("void*" if is_unk else pt+"*")), "high"
        elif str_use:
            pt, conf = "const char*", "medium"
        elif mem_use:
            pt, conf = ("void*" if not pt.endswith("*") else pt), "medium"
        ps.append({"name": n, "type": pt, "conf": conf})
        
    kind = "cpp_export" if name.startswith("?") else ("internal" if name.startswith(("FUN_","sub_")) else "c_export")
    return {"kind": kind, "function_name": name, "return_type": ret.strip(), "calling_convention": cc, "params": ps}

def main():
    if len(sys.argv) < 2:
        print("Usage: py script.py in.txt [out.json]")
        return
    txt = Path(sys.argv[1]).read_text("utf-8", "ignore")
    out = {n: infer(r, n, a, b) for r, n, a, b in extract_funcs(txt)}
    out_file = sys.argv[2] if len(sys.argv) > 2 else "out.json"
    Path(out_file).write_text(json.dumps(out, indent=2))
    print(f"Parsed {len(out)} functions successfully.")

if __name__ == "__main__":
    main()
