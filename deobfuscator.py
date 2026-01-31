Orange = '\033[38;5;208m'
Reset = '\033[0m'


import sys
import ast
import base64
import zlib
import itertools
import re
from typing import Dict, List, Tuple, Optional
import dis

class SoberDeobfuscator:
    
    def __init__(self, obfcode: str):
        self.code = obfcode
        self.ast = ast.parse(obfcode)
        self.variables: Dict[str, str] = {}
        self.bytes_variables: Dict[str, bytes] = {}
        self.decoy_indicators = []
        self.extracted_source = None
        
    def StringAssignments(self) -> None:
        for node in ast.walk(self.ast):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        VarName = target.id
                        value = node.value

                        # Python 3.8+: ast.Constant

                        if isinstance(value, ast.Constant):
                            if isinstance(value.value, str):
                                self.variables[VarName] = value.value
                            elif isinstance(value.value, bytes):
                                self.bytes_variables[VarName] = value.value

                        # Python <3.8: ast.Str, ast.Bytes

                        elif hasattr(ast, 'Str') and isinstance(value, ast.Str):
                            self.variables[VarName] = value.s
                        elif hasattr(ast, 'Bytes') and isinstance(value, ast.Bytes):
                            self.bytes_variables[VarName] = value.s
                            
    def EntryPoint(self) -> Optional[ast.Exec]:
        for node in ast.walk(self.ast):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    call = node.value
                    if isinstance(call.func, ast.Name) and call.func.id == 'exec':
                        return call
                    if self.IsExecCall(call):
                        return call
        return None
    
    def IsExecCall(self, node: ast.Call) -> bool:
        try:
            code = ast.unparse(node)
            return 'exec(' in code or '__builtins__.exec' in code
        except:
            return False
            
    def ExecPayload(self, exec_node: ast.Call) -> Tuple[str, str, bytes]:
        ExecSource = ast.unparse(exec_node)
        pattern = r"b85decode\(([^)]+)\),\s*([\w_]+)\)"
        match = re.search(pattern, ExecSource)
        if match:
            B85Var = match.group(1).strip()
            KeyVar = match.group(2).strip()
    
            key = self.bytes_variables.get(KeyVar)
            if not key:
                
                KeyPattern = rf"{KeyVar}\s*=\s*(b['\"].*?['\"])"
                key_match = re.search(KeyPattern, self.code, re.DOTALL)

                if key_match:
                    key = eval(key_match.group(1))

            return B85Var, KeyVar, key

        # if not found
        JoinPattern = r"''\.join\((\w+)\)"
        JoinMatch = re.search(JoinPattern, ExecSource)
        if JoinMatch:
            JoinedVar = JoinMatch.group(1)
            ListPattern = rf"{JoinedVar}\s*=\s*\[(.*?)\]"
            ListMatch = re.search(ListPattern, self.code, re.DOTALL)
            if ListMatch:
                VarNames = re.findall(r'(\w+)', ListMatch.group(1))
                for node in ast.walk(self.ast):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if isinstance(node.value, ast.Call):
                                    func = node.value.func
                                    if isinstance(func, ast.Attribute) and func.attr == 'join':
                                        JoinedName = target.id
                                        KeyVar = None
                                        key = None
                                        for node2 in ast.walk(self.ast):
                                            if isinstance(node2, ast.Assign):
                                                for t2 in node2.targets:
                                                    if isinstance(t2, ast.Name):
                                                        if isinstance(node2.value, ast.Constant) and isinstance(node2.value.value, bytes):
                                                            KeyVar = t2.id
                                                            key = node2.value.value
                                        if not key:
                                          
                                            KeyPattern = r"(\w+)\s*=\s*(b['\"].*?['\"])"
                                            for m in re.finditer(KeyPattern, self.code):
                                                KeyVar = m.group(1)
                                                key = eval(m.group(2))
                                                break
                                        return JoinedName, KeyVar, key
        raise ValueError("Cannot parse exec payload structure")
    
    def FindXorKey(self) -> bytes:
        for VarName, value in self.variables.items():
            if VarName.startswith('_') and len(VarName) > 8:   
                pass

        BytesPattern = r"(b['\"].{10,}['\"])"
        for match in re.finditer(BytesPattern, self.code):
            try:
                potential = eval(match.group(1))
                if isinstance(potential, bytes) and len(potential) >= 8:
                    return potential
            except:
                continue
                
        raise ValueError("XOR key not found")
    
    def Reconstruction(self, B85Var: str, key: bytes) -> str:
        B85String = self.variables.get(B85Var, None)
        if B85String is None:
            for node in ast.walk(self.ast):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == B85Var:
                            if isinstance(node.value, ast.Call):
                                call = node.value
                                if isinstance(call.func, ast.Attribute) and call.func.attr == 'join':
                                    if call.args and isinstance(call.args[0], ast.Name):
                                        list_var = call.args[0].id
                                        for node2 in ast.walk(self.ast):
                                            if isinstance(node2, ast.Assign):
                                                for t2 in node2.targets:
                                                    if isinstance(t2, ast.Name) and t2.id == list_var:
                                                        if isinstance(node2.value, ast.List):
                                                            VarNames = []
                                                            for elt in node2.value.elts:
                                                                if isinstance(elt, ast.Name):
                                                                    VarNames.append(elt.id)
                                                            B85String = ''.join(self.variables.get(var, '') for var in VarNames)
        if not B85String:
            raise ValueError("Cannot reconstruct base85 payload")
        try:
            encrypted = base64.b85decode(B85String)
            decrypted = bytes(a ^ b for a, b in zip(encrypted, itertools.cycle(key)))
            decompressed = zlib.decompress(decrypted)
            original = decompressed.decode('utf-8')
            return original
        except Exception as e:
            raise ValueError(f"Payload reconstruction failed: {e}")
    
    def deobfuscate(self) -> str:
        print(f" [{Orange}*{Reset}] Extracting string assignments...")
        self.StringAssignments()
        print(f" [{Orange}*{Reset}] Found {len(self.variables)} string variables")
        print(f" [{Orange}*{Reset}] Found {len(self.bytes_variables)} bytes variables")
        print(f" [{Orange}*{Reset}] Searching for exec statement...")
        exec_node = self.EntryPoint()
        if not exec_node:
            raise ValueError("No exec statement found in code")
        print(f" [{Orange}*{Reset}] Analyzing exec payload structure...")
        B85Var, KeyVar, key = self.ExecPayload(exec_node)
        print(f" [{Orange}+{Reset}] Base85 variable: {B85Var}")
        print(f" [{Orange}+{Reset}] Key variable: {KeyVar}")
        print(f" [{Orange}+{Reset}] Key length: {len(key) if key else 0}")
        print(f" [{Orange}*{Reset}] Reconstructing original source...")
        original = self.Reconstruction(B85Var, key)
        self.extracted_source = original
        return original
    
    def generate_clean_output(self, output_path: str = None) -> str:
        if not self.extracted_source:
            self.deobfuscate()
        
        clean_code = f"""# SHΔDØW-DEOB RECOVERY
# Original code extracted from obfuscated payload
# Recovery timestamp: {__import__('datetime').datetime.now()}
# Deobfuscator: SHΔDØW CORE v99.7

{self.extracted_source}
"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(clean_code)
            print(f" [{Orange}/{Reset}] Clean code written to: {output_path}")
        
        return clean_code


class GenDeobfuscator:
    
    @staticmethod
    def StaticDeobfuscate(code: str) -> str:

        patterns = [
            r"exec\(.*?b85decode\((.*?\).*?\)",
            r"''\.join\(\[.*?\]\)",
            r"b['\"].*?['\"]"
        ]
        
        # Extract all suspicious strings (base85 encoded)
        B85Pattern = r"['\"]([0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]{15,})['\"]"
        AllStrings = re.findall(B85Pattern, code)
        
        # Filter decoys (random strings vs actual base85)
        def is_likely_base85(s: str) -> bool:
            base85_chars = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
            return all(c in base85_chars for c in s) and len(s) >= 20
        
        LikelyPayloadList = [s for s in AllStrings if is_likely_base85(s)]
        
        for candidate in LikelyPayloadList:
            try:
                decoded = base64.b85decode(candidate)
                
                for key_len in [8, 16, 32]:
                    PotentialData = decoded[:key_len]
                    
                    TestData = decoded[:100]
                    decrypted = bytes(a ^ b for a, b in zip(TestData, itertools.cycle(PotentialData)))
                    
                    try:
                        decompressed = zlib.decompress(decrypted)
                        if decompressed[:20].decode('utf-8', errors='ignore').isprintable():
                            FullDecrypt = bytes(a ^ b for a, b in zip(decoded, itertools.cycle(PotentialData)))
                            return zlib.decompress(FullDecrypt).decode('utf-8')
                    except:
                        continue
            except:
                continue
        
        raise ValueError("Static analysis failed - try AST-based approach")
    
    @staticmethod
    def bruteforce(code: str, max_key_length: int = 32) -> str:

        BytePattern = r"b['\"](.*?)['\"]"
        ByteStrings = []
        
        for match in re.finditer(BytePattern, code, re.DOTALL):
            try:
                byte_str = eval(f"b'{match.group(1)}'")
                if len(byte_str) >= 8:
                    ByteStrings.append(byte_str)
            except:
                continue
        
        B85Pattern = r"['\"]([0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]{20,})['\"]"
        Base85Strings = re.findall(B85Pattern, code)
        
        for b85_str in Base85Strings:
            for key in ByteStrings:
                try:
                    decoded = base64.b85decode(b85_str)
                    decrypted = bytes(a ^ b for a, b in zip(decoded, itertools.cycle(key)))
                    decompressed = zlib.decompress(decrypted)
                    
                    if b'def ' in decompressed or b'import ' in decompressed or b'class ' in decompressed:
                        return decompressed.decode('utf-8')
                except:
                    continue
        
        raise ValueError("Brute force deobfuscation failed")

def Deobfuscate_File(filepath: str, destination: str = None, method: str = "ast"):
    with open(filepath, 'r', encoding='utf-8') as f:
        obfcode = f.read()
    
    print(f" [{Orange}*{Reset}] Loaded {len(obfcode)} bytes from {filepath}")
    
    if method == "ast":
        deob = SoberDeobfuscator(obfcode)
        try:
            original = deob.deobfuscate()
        except Exception as e:
            print(f" [{Orange}!{Reset}] AST method failed: {e}")
            print(f" [{Orange}*{Reset}] Falling back to static analysis...")
            original = GenDeobfuscator.StaticDeobfuscate(obfcode)
    else:
        original = GenDeobfuscator.StaticDeobfuscate(obfcode)
    print(f" [{Orange}/{Reset}] Successfully recovered {len(original)} characters of original code")
    if destination:
        with open(destination, 'w', encoding='utf-8') as f:
            f.write(original)
        print(f" [{Orange}/{Reset}] Saved to: {destination}")
    return original

if __name__ == "__main__":
    import os
    os.system("")
    os.system('cls' if os.name == 'nt' else 'clear'); os.system("title WhatThePy Deobfuscator" if os.name == 'nt' else "")

    minibanner = f"""
 {Orange}WhatThePy{Reset} Deobfuscator
 Developed by soberized
 {Orange}https://github.com/soberized{Reset}"""
    print(minibanner)


    def normalize_path(path):
        # Detect MSYS/Cygwin style: /c/Users/...
        import re, os
        msys_match = re.match(r"^/([a-zA-Z])/(.*)", path)
        if msys_match:
            drive = msys_match.group(1).upper()
            rest = msys_match.group(2).replace('/', '\\')
            win_path = f"{drive}:\\{rest}"
            print(f" [{Orange}!{Reset}] MSYS path detected. Normalized to: {win_path}")
            return win_path
        return path

    if len(sys.argv) >= 2:
        print(f"\n[{Orange}+{Reset}] System arguments detected:")
        for idx, arg in enumerate(sys.argv[1:], 1):
            print(f"    [{Orange}{idx}{Reset}] {arg}")
        filepath = normalize_path(sys.argv[1])
        destination = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated_output.py"
    else:
        filepath = input(f"\n [{Orange}?{Reset}] File Path: ").strip()
        filepath = normalize_path(filepath)
        destination = input(f" [{Orange}?{Reset}] Output Path [deobfuscated_output.py]: ").strip() or "deobfuscated_output.py"
    try:
        Deobfuscate_File(filepath, destination, method="ast")
        print(f"\n [{Orange}/{Reset}] Deobfuscation complete. Target decompiled.")
    except Exception as e:
        print(f"\n [{Orange}X{Reset}] Deobfuscation failed: {e}")
        print(f" [{Orange}*{Reset}] Attempting alternative methods...")


    # Fallback
    
        with open(filepath, 'r') as f:
            code = f.read()
        try:
            result = GenDeobfuscator.bruteforce(code)
            with open(destination + ".brute", 'w') as f:
                f.write(result)
            print(f" [{Orange}/{Reset}] Brute force recovery saved to {destination}.brute")
        except:
            print(f" [{Orange}X{Reset}] All recovery methods exhausted.")