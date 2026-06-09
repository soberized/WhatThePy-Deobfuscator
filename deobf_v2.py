import ast
import hashlib
import os
import struct
import sys
import zlib

Orange = '\033[38;5;208m'
Reset = '\033[0m'


def _collect_loaded_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            names.add(sub.id)
    return names


def _find_key_function(tree: ast.Module) -> ast.FunctionDef:
    candidates: list[ast.FunctionDef] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.args.args or node.args.kwonlyargs or node.args.vararg or node.args.kwarg:
            continue
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
            continue
        ret = node.body[0].value
        if not isinstance(ret, ast.Call):
            continue
        if not isinstance(ret.func, ast.Name) or ret.func.id != "bytes":
            continue
        if len(ret.args) != 1 or not isinstance(ret.args[0], ast.Call):
            continue
        inner = ret.args[0]
        if not isinstance(inner.func, ast.Name):
            continue
        candidates.append(node)

    if not candidates:
        raise ValueError("Could not find key function")

    return candidates[-1]


def _build_key_from_ast(obfuscated_source: str) -> bytes:
    tree = ast.parse(obfuscated_source)
    key_fn = _find_key_function(tree)

    assigns: dict[str, ast.Assign] = {}
    funcs: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigns[node.targets[0].id] = node
        elif isinstance(node, ast.FunctionDef):
            funcs[node.name] = node

    needed: set[str] = {key_fn.name}
    queue: list[str] = [key_fn.name]

    while queue:
        name = queue.pop()
        if name in funcs:
            node = funcs[name]
            refs = _collect_loaded_names(node)
        elif name in assigns:
            node = assigns[name]
            refs = _collect_loaded_names(node.value)
        else:
            continue

        for ref in refs:
            if ref in {"bytes", "range", "len"}:
                continue
            if ref not in needed and (ref in funcs or ref in assigns):
                needed.add(ref)
                queue.append(ref)

    selected: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in needed:
                    selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in needed:
            selected.append(node)

    sandbox_env: dict[str, object] = {
        "__builtins__": {"bytes": bytes, "range": range, "len": len}
    }
    mod = ast.Module(body=selected, type_ignores=[])
    code = compile(mod, "<key_extract>", "exec")
    exec(code, sandbox_env, sandbox_env)

    key_fn_obj = sandbox_env.get(key_fn.name)
    if key_fn_obj is None:
        raise ValueError("Failed to evaluate key function")

    key = key_fn_obj()
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("Recovered key is not bytes")

    return bytes(key)


def _decrypt_fast_cipher(key: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    block = 32
    for i in range(0, len(data), block):
        ctr = (i // block).to_bytes(8, "little")
        ks = hashlib.sha256(key + ctr).digest()
        chunk = data[i : i + block]
        for j, b in enumerate(chunk):
            out[i + j] = b ^ ks[j]
    return bytes(out)


def _derive_dat_path(obfuscated_path: str) -> str:
    folder = os.path.dirname(os.path.abspath(obfuscated_path))
    stem = os.path.splitext(os.path.basename(obfuscated_path))[0]
    dat_stem = stem.replace("_obfuscated", "")
    candidate = os.path.join(folder, f"{dat_stem}_payload.dat")
    if os.path.exists(candidate):
        return candidate

    files = sorted(x for x in os.listdir(folder) if x.endswith("_payload.dat"))
    if len(files) == 1:
        return os.path.join(folder, files[0])

    raise FileNotFoundError(f"Could not infer dat payload path from {obfuscated_path}")


def deobfuscate_v2(obfuscated_path: str, dat_path: str | None = None) -> str:
    print(f" [{Orange}*{Reset}] Loading obfuscated source...")
    with open(obfuscated_path, "r", encoding="utf-8") as f:
        obf_src = f.read()
    print(f" [{Orange}+{Reset}] Loaded {len(obf_src)} characters")

    print(f" [{Orange}*{Reset}] Reconstructing embedded key...")
    key = _build_key_from_ast(obf_src)
    print(f" [{Orange}+{Reset}] Key length: {len(key)} bytes")

    if dat_path is None:
        print(f" [{Orange}*{Reset}] Resolving payload path...")
        dat_path = _derive_dat_path(obfuscated_path)
    print(f" [{Orange}+{Reset}] Payload path: {dat_path}")

    print(f" [{Orange}*{Reset}] Reading payload blob...")
    with open(dat_path, "rb") as f:
        dat = f.read()
    print(f" [{Orange}+{Reset}] Payload size: {len(dat)} bytes")

    if len(dat) < 8 or dat[:4] != b"WTPY":
        raise ValueError("Invalid .dat payload: missing WTPY magic")

    section_len = struct.unpack(">I", dat[4:8])[0]
    section = dat[8 : 8 + section_len]
    if len(section) != section_len:
        raise ValueError("Invalid .dat payload: truncated section")

    print(f" [{Orange}*{Reset}] Decrypting and decompressing payload...")
    salt = section[:16]
    ciphertext = section[16:]
    block_key = hashlib.sha256(key + salt).digest()
    compressed = _decrypt_fast_cipher(block_key, ciphertext)
    source = zlib.decompress(compressed).decode("utf-8")
    print(f" [{Orange}/{Reset}] Recovered {len(source)} characters of original source")
    return source


def normalize_path(path: str) -> str:
    import re

    msys_match = re.match(r"^/([a-zA-Z])/(.*)", path)
    if msys_match:
        drive = msys_match.group(1).upper()
        rest = msys_match.group(2).replace('/', '\\')
        win_path = f"{drive}:\\{rest}"
        print(f" [{Orange}!{Reset}] MSYS path detected. Normalized to: {win_path}")
        return win_path
    return path


def main() -> int:
    os.system("")
    os.system('cls' if os.name == 'nt' else 'clear')
    os.system("title WhatThePy Deobfuscator" if os.name == 'nt' else "")

    minibanner = f"""
 {Orange}WhatThePy{Reset} Deobfuscator
 Developed by soberized
 {Orange}https://github.com/soberized{Reset}"""
    print(minibanner)

    if len(sys.argv) < 2:
        print(f"\n [{Orange}?{Reset}] Usage: py deobf_v2.py <obfuscated.py> [payload.dat] [output.py]")
        return 1

    args = sys.argv[1:]
    print(f"\n[{Orange}+{Reset}] System arguments detected:")
    for idx, arg in enumerate(args, 1):
        print(f"    [{Orange}{idx}{Reset}] {arg}")

    obf_path = normalize_path(args[0])
    dat_path = None
    out_path = "deobfuscated_output_v2.py"

    if len(args) == 2:
        candidate = normalize_path(args[1])
        if candidate.lower().endswith(".dat") or os.path.basename(candidate).endswith("_payload.dat"):
            dat_path = candidate
        else:
            out_path = candidate
    elif len(args) >= 3:
        dat_path = normalize_path(args[1])
        out_path = normalize_path(args[2])

    recovered = deobfuscate_v2(obf_path, dat_path)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(recovered)

    print(f" [{Orange}/{Reset}] Saved to: {out_path}")
    print(f"\n [{Orange}/{Reset}] Deobfuscation complete. Target decompiled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
