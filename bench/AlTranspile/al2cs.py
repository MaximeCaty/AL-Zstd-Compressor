#!/usr/bin/env python3
"""
AL -> C# transpiler for testing pure-AL codeunits off-BC (the subset used by the TOO codecs).

It maps AL constructs one for one so the generated C# behaves like the AL :
  - 1-based arrays with bound checks (ALArray), Text as a value type with 1-based char indexing (ALText / ALChar) ;
  - Integer = checked int (overflow errors as in AL), BigInteger = long ;
  - `and` / `or` evaluate both sides (C# & / |), like AL ;
  - `for` bounds evaluated once ; `case` = if chain ; `exit` / named return values ;
  - var parameters of value types -> ref ; arrays, TextBuilder, streams, codeunits are reference objects ;
  - Labels -> ALText constants ; DotNet_* / Temp Blob / NavApp -> stubs of AlRuntime.cs.
Usage : al2cs.py <codeunit.al> <enum.al>... > Out.cs
"""
import re, sys

# ----------------------------------------------------------------------------------------------------------- tokenizer
TOK = re.compile(r"""
    (?P<ws>\s+)|(?P<lc>//[^\n]*)|(?P<bc>/\*.*?\*/)|(?P<pp>\#[^\n]*)|
    (?P<str>'(?:[^']|'')*')|(?P<qid>"[^"]*")|(?P<num>\d+L?)|(?P<id>[A-Za-z_][A-Za-z0-9_]*)|
    (?P<op>:=|\+=|-=|\*=|/=|::|<>|<=|>=|\.\.|[()\[\];,:.+\-*/=<>{}])""", re.S | re.X)

def tokenize(src):  # tokens (kind, value, AL source line)
    out = []
    line = 1; last = 0
    for m in TOK.finditer(src):
        k = m.lastgroup
        if k in ('ws', 'lc', 'bc', 'pp'):
            continue
        line += src.count('\n', last, m.start()); last = m.start()
        out.append((k, m.group(k), line))
    return out

KW = {'begin', 'end', 'if', 'then', 'else', 'while', 'do', 'repeat', 'until', 'for', 'to', 'downto', 'case', 'of',
      'exit', 'break', 'var', 'procedure', 'local', 'and', 'or', 'not', 'xor', 'div', 'mod', 'foreach', 'in', 'true', 'false'}

class P:
    def __init__(self, toks):
        self.t = toks; self.i = 0
    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else ('eof', '', 0)
    def v(self, k=0):
        tk = self.peek(k); return tk[1].lower() if tk[0] == 'id' else tk[1]
    def next(self):
        tk = self.t[self.i]; self.i += 1; return tk
    def expect(self, val):
        tk = self.next()
        got = tk[1].lower() if tk[0] == 'id' else tk[1]
        if got != val.lower():
            raise SyntaxError(f"expected {val} got {tk} near {self.t[self.i-5:self.i+5]}")
        return tk
    def accept(self, val):
        if self.v() == val.lower():
            self.i += 1; return True
        return False

def cname(q):  # "TOO Brotli Level" -> TOO_Brotli_Level
    return re.sub(r'[^A-Za-z0-9_]', '_', q.strip('"'))

# ----------------------------------------------------------------------------------------------------------- types
def parse_type(p):
    """returns dict(kind=..., elem=..., size=..., name=...)"""
    w = p.v()
    if w == 'array':
        p.next(); p.expect('['); size = int(p.next()[1]); p.expect(']'); p.expect('of')
        el = parse_type(p)
        return {'kind': 'array', 'size': size, 'elem': el}
    if w == 'list':
        p.next(); p.expect('of'); p.expect('['); el = parse_type(p); p.expect(']')
        return {'kind': 'list', 'elem': el}
    if w == 'codeunit':
        p.next(); tk = p.next(); return {'kind': 'codeunit', 'name': cname(tk[1])}
    if w == 'enum':
        p.next(); tk = p.next(); return {'kind': 'enum', 'name': cname(tk[1])}
    if w == 'label':
        p.next(); s = p.next()[1]
        while p.v() == ',':   # Comment = '...', Locked = true
            p.next(); p.next(); p.expect('='); p.next()
        return {'kind': 'label', 'value': s}
    tk = p.next(); n = tk[1].lower()
    if n == 'text' and p.v() == '[':
        p.next(); p.next(); p.expect(']')
    m = {'integer': 'int', 'biginteger': 'long', 'boolean': 'bool', 'text': 'text', 'char': 'char', 'byte': 'byte',
         'textbuilder': 'tb', 'instream': 'instream', 'outstream': 'outstream'}
    if n not in m:
        raise SyntaxError('type ' + n)
    return {'kind': m[n]}

def cs_type(t):
    k = t['kind']
    return {'int': 'int', 'long': 'long', 'bool': 'bool', 'text': 'ALText', 'char': 'ALChar', 'byte': 'byte',
            'tb': 'ALTextBuilder', 'instream': 'ALInStream', 'outstream': 'ALOutStream'}.get(k) or \
        (f"ALArray<{cs_type(t['elem'])}>" if k == 'array' else f"ALList<{cs_type(t['elem'])}>" if k == 'list'
         else t['name'] if k in ('codeunit', 'enum') else 'ALText')

def cs_init(t):
    k = t['kind']
    if k == 'array': return f"new {cs_type(t)}({t['size']})"
    if k in ('list', 'tb', 'instream', 'outstream', 'codeunit'): return f"new {cs_type(t)}()"
    if k == 'text': return '""'
    if k == 'bool': return 'false'
    if k == 'enum': return 'default'
    if k == 'char': return 'default'
    return '0'

VALUE_KINDS = ('int', 'long', 'bool', 'text', 'char', 'byte', 'enum')

def conv(t, e):
    k = t['kind'] if t else None
    if k == 'int': return f"ALRt.I({e})"
    if k == 'long': return f"ALRt.L({e})"
    if k == 'char': return f"ALRt.C({e})"
    if k == 'byte': return f"ALRt.B({e})"
    if k == 'text': return f"ALRt.T({e})"
    return e

def cs_str(s):
    body = s[1:-1].replace("''", "'")
    return '"' + ''.join('\\"' if c == '"' else '\\\\' if c == '\\' else c for c in body) + '"'

# ----------------------------------------------------------------------------------------------------------- codeunit
class Tr:
    def __init__(self, enums, count=False):
        self.globals = {}; self.procs = {}; self.out = []; self.tmp = 0; self.enums = enums
        self.count = count; self.pnames = []; self.pid = 0

    def hit(self, ln):  # statement counter (AL StmtHit) of the current procedure and AL line, as a C# bool term
        return f"ALRt.H({self.pid}, {ln}) & " if self.count else ""

    def cnt(self, pad, ln):
        return [pad + f"ALRt.S[{self.pid}]++; ALRt.LS[{ln}]++;"] if self.count else []

    def fresh(self):
        self.tmp += 1; return f"__t{self.tmp}"

    def run(self, src):
        p = P(tokenize(src))
        p.expect('codeunit'); p.next(); cu = cname(p.next()[1]); p.expect('{')
        while p.v() not in ('var', 'procedure', 'local', '}', '['):
            p.next()
        if p.accept('var'):
            while p.v() not in ('procedure', 'local', '}', '['):
                name = p.next()[1]; p.expect(':'); t = parse_type(p); p.accept(';')
                self.globals[name.lower()] = (name, t)
        # pre-scan procedures (signatures)
        procs = []
        while p.v() != '}':
            while p.v() == '[':  # attributes
                while p.next()[1] != ']': pass
            local = p.accept('local')
            p.expect('procedure')
            name = p.next()[1]; p.expect('(')
            params = []
            while p.v() != ')':
                isvar = p.accept('var')
                pn = p.next()[1]; p.expect(':'); pt = parse_type(p)
                params.append((pn, pt, isvar)); p.accept(';')
            p.expect(')')
            ret = None; retname = None
            if p.v() == ':':
                p.next(); ret = parse_type(p)
            elif p.peek()[0] == 'id' and p.v(1) == ':':
                retname = p.next()[1]; p.next(); ret = parse_type(p)
            p.accept(';')
            locs = []
            if p.accept('var'):
                while p.v() != 'begin':
                    ln = p.next()[1]; p.expect(':'); lt = parse_type(p); p.accept(';')
                    locs.append((ln, lt))
            start = p.i
            depth = 0
            while True:  # skip body to find its end (begin/case ... end)
                w = p.v()
                if w in ('begin', 'case'): depth += 1
                elif w == 'end':
                    depth -= 1
                    if depth == 0:
                        p.next(); p.accept(';'); break
                p.next()
            procs.append((name, params, ret, retname, locs, start, p.i))
            self.procs.setdefault(name.lower(), []).append((params, ret))
        self.p = p
        o = self.out
        o.append("// <auto-generated> al2cs.py from the AL codeunit - do not edit </auto-generated>")
        o.append("#pragma warning disable CS0162, CS0164, CS0168, CS0219, CS1717")
        o.append("namespace AlGen;")
        o.append(f"public sealed class {cu}\n{{")
        for key, (name, t) in self.globals.items():
            if t['kind'] == 'label':
                o.append(f"    static readonly ALText {name} = {cs_str(t['value'])};")
            else:
                o.append(f"    public {cs_type(t)} {name} = {cs_init(t)};")
        for pr in procs:
            self.emit_proc(*pr)
        names = ', '.join('"' + n + '"' for n in self.pnames)
        o.append(f"    public static readonly string[] ProcNames = {{ {names} }};")
        o.append("}")
        return "\n".join(o)

    # ------------------------------------------------------------------------------------------------ procedures
    def emit_proc(self, name, params, ret, retname, locs, start, endi):
        self.scope = {k: v for k, v in self.globals.items()}
        self.ret = ret; self.retname = retname
        ps = []
        for pn, pt, isvar in params:
            self.scope[pn.lower()] = (pn, pt)
            ref = 'ref ' if isvar and pt['kind'] in VALUE_KINDS else ''
            ps.append(f"{ref}{cs_type(pt)} {pn}")
        rt = cs_type(ret) if ret else 'void'
        self.out.append(f"    public {rt} {name}({', '.join(ps)})\n    {{")
        self.pid = len(self.pnames); self.pnames.append(name)
        if self.count:
            self.out.append(f"        ALRt.Calls[{self.pid}]++;")
        for ln, lt in locs:
            self.scope[ln.lower()] = (ln, lt)
            self.out.append(f"        {cs_type(lt)} {ln} = {cs_init(lt)};")
        if retname:
            self.scope[retname.lower()] = (retname, ret)
            self.out.append(f"        {cs_type(ret)} {retname} = {cs_init(ret)};")
        p = self.p; p.i = start
        p.expect('begin')
        body = self.stmts(p, ('end',), 2)
        p.expect('end')
        self.out.extend(body)
        if retname:
            self.out.append(f"        return {retname};")
        elif ret:
            self.out.append(f"        return default;")
        self.out.append("    }")

    # ------------------------------------------------------------------------------------------------ statements
    def stmts(self, p, stops, ind):
        res = []
        while p.v() not in stops:
            if p.accept(';'):
                continue
            res.extend(self.stmt(p, ind))
            p.accept(';')
        return res

    def block(self, p, ind):
        s = self.stmt(p, ind + 1)
        pad = '    ' * ind
        return [pad + '{'] + s + [pad + '}']

    def stmt(self, p, ind):
        pad = '    ' * ind
        w = p.v(); ln = p.peek()[2]
        if w == 'begin':
            p.next(); s = self.stmts(p, ('end',), ind); p.expect('end')
            return [pad + '{'] + s + [pad + '}']
        if w == 'if':
            p.next(); c = self.expr(p); p.expect('then')
            res = [pad + f"if ({self.hit(ln)}({c}))"]
            if p.v() == 'else':
                res += [pad + '{', pad + '}']
            else:
                res += self.block(p, ind)
            if p.v() == 'else':
                p.next(); res += [pad + 'else'] + self.block(p, ind)
            return res
        if w == 'while':
            p.next(); c = self.expr(p); p.expect('do')
            return [pad + f"while ({self.hit(ln)}({c}))"] + self.block(p, ind)
        if w == 'repeat':
            p.next(); s = self.stmts(p, ('until',), ind + 1); ln = p.peek()[2]; p.expect('until'); c = self.expr(p)
            return [pad + 'do', pad + '{'] + s + [pad + f"}} while (!({self.hit(ln)}({c})));"]
        if w == 'for':
            p.next(); var = p.next()[1]; p.expect(':='); a = self.expr(p)
            down = p.v() == 'downto'; p.next(); b = self.expr(p); p.expect('do')
            t = self.fresh(); vn, vt = self.lookup(var)
            # BC counts a for statement once (StmtHit before the loop), not its test per iteration
            head = [pad + '{'] + self.cnt(pad + '    ', ln) + [pad + f"    long {t} = {b};",
                    pad + f"    for ({vn} = ALRt.I({a}); ({vn} {'>=' if down else '<='} {t}); {vn}{'--' if down else '++'})"]
            return head + self.block(p, ind + 1) + [pad + '}']
        if w == 'foreach':
            p.next(); var = p.next()[1]; p.expect('in'); coll = self.expr(p); p.expect('do')
            t = self.fresh(); vn, vt = self.lookup(var)
            return [pad + f"foreach (var {t} in {coll})", pad + '{', pad + f"    {vn} = {t};"] + self.block(p, ind + 1) + [pad + '}']
        if w == 'case':
            p.next(); e = self.expr(p); p.expect('of')
            t = self.fresh()
            res = [pad + '{'] + self.cnt(pad + '    ', ln) + [pad + f"    var {t} = {e};"]
            first = True
            while p.v() not in ('end', 'else'):
                vals = [self.expr(p)]
                while p.accept(','):
                    vals.append(self.expr(p))
                p.expect(':')
                cond = ' || '.join(f"({t} == {v})" for v in vals)
                res += [pad + f"    {'if' if first else 'else if'} ({cond})"] + self.block(p, ind + 1)
                first = False
                p.accept(';')
            if p.accept('else'):
                s = self.stmts(p, ('end',), ind + 2)
                res += [pad + '    else', pad + '    {'] + s + [pad + '    }']
            p.expect('end')
            return res + [pad + '}']
        if w == 'exit':
            p.next()
            if p.accept('('):
                e = self.expr(p); p.expect(')')
                return self.cnt(pad, ln) + [pad + f"return {conv(self.ret, e)};"]
            return self.cnt(pad, ln) + [pad + (f"return {self.retname};" if self.retname else "return;")]
        if w == 'break':
            p.next(); return self.cnt(pad, ln) + [pad + 'break;']
        # assignment or call
        lhs_i = p.i
        lhs = self.expr(p, lvalue=True)
        op = p.v()
        if op in (':=', '+=', '-=', '*='):
            t = self.lhs_type; ischar = self.lhs_is_char_index
            p.next(); rhs = self.expr(p)
            if op != ':=':
                rhs = f"{lhs} {op[0]} ({rhs})"
            if ischar:
                return self.cnt(pad, ln) + [pad + f"{lhs} = ALRt.C({rhs});"]
            return self.cnt(pad, ln) + [pad + f"{lhs} = {conv(t, rhs)};"]
        return self.cnt(pad, ln) + [pad + lhs + ';']

    def lookup(self, name):
        k = name.lower()
        if k in self.scope:
            return self.scope[k]
        raise NameError(name)

    # ------------------------------------------------------------------------------------------------ expressions
    # AL precedence : relational < additive (+ - or xor) < multiplicative (* / div mod and) < unary (not -)
    def expr(self, p, lvalue=False):
        self.lhs_type = None; self.lhs_is_char_index = False
        return self.rel(p)

    def rel(self, p):
        l = self.add(p)
        while p.v() in ('=', '<>', '<', '<=', '>', '>='):
            op = p.next()[1]; r = self.add(p)
            op = {'=': '==', '<>': '!='}.get(op, op)
            l = f"({l} {op} {r})"
        return l

    def add(self, p):
        l = self.mul(p)
        while p.v() in ('+', '-', 'or', 'xor'):
            op = p.v(); p.next(); r = self.mul(p)
            op = {'or': '|', 'xor': '^'}.get(op, op)
            l = f"({l} {op} {r})"
        return l

    def mul(self, p):
        l = self.unary(p)
        while p.v() in ('*', '/', 'div', 'mod', 'and'):
            op = p.v(); p.next(); r = self.unary(p)
            op = {'div': '/', 'mod': '%', 'and': '&'}.get(op, op)
            l = f"({l} {op} {r})"
        return l

    def unary(self, p):
        if p.accept('not'):
            return f"(!{self.unary(p)})"
        if p.accept('-'):
            return f"(-{self.unary(p)})"
        if p.accept('+'):
            return self.unary(p)
        return self.postfix(p)

    def args(self, p):
        a = []
        p.expect('(')
        while p.v() != ')':
            a.append(self.expr_keep(p)); p.accept(',')
        p.expect(')')
        return a

    def expr_keep(self, p):
        save = (self.lhs_type, self.lhs_is_char_index)
        e = self.rel(p)
        self.lhs_type, self.lhs_is_char_index = save
        return e

    def postfix(self, p):
        tk = p.next()
        k, val = tk[0], tk[1]
        typ = None
        if k == 'num':
            e = val
        elif k == 'str':
            e = cs_str(val)
        elif val == '(':
            e = '(' + self.expr_keep(p) + ')'; p.expect(')')
        elif k == 'id' and val.lower() in ('true', 'false'):
            e = val.lower()
        elif k == 'id' and val.lower() == 'enum' and p.v() == '::':
            p.next(); en = cname(p.next()[1]); p.expect('::'); m = p.next()[1]
            return f"{en}.{m}"
        elif k == 'id':
            low = val.lower()
            if p.v() == '::':  # Level::Fast
                p.next(); m = p.next()[1]
                _, t = self.lookup(val)
                return f"{t['name']}.{m}"
            if low == 'navapp' and p.v() == '.':
                p.next(); m = p.next()[1]; a = self.args(p)
                return f"NavApp.{m}({', '.join(a)})"
            if low in self.procs and low not in self.scope:
                a = self.args(p) if p.v() == '(' else []
                return self.call(val, a)
            if low in ('strlen', 'clear', 'evaluate', 'error'):
                return self.builtin(p, low)
            name, typ = self.lookup(val)
            e = name
        else:
            raise SyntaxError(f"unexpected {tk} near {p.t[p.i-5:p.i+5]}")
        self.lhs_type = typ
        # postfix : index, member
        while True:
            if p.v() == '[':
                p.next(); idx = self.expr_keep(p); p.expect(']')
                if typ and typ['kind'] == 'array':
                    e = f"{e}[{idx}]"; typ = typ['elem']; self.lhs_type = typ
                else:  # text char
                    e = f"{e}[{idx}]"; self.lhs_type = typ; self.lhs_is_char_index = True
                    typ = {'kind': 'char'}
            elif p.v() == '.':
                p.next(); m = p.next()[1]
                a = self.args(p) if p.v() == '(' else []
                e = f"{e}.{m}({', '.join(a)})"
                typ = None; self.lhs_type = None
            else:
                break
        return e

    def call(self, name, a):
        sigs = self.procs[name.lower()]
        sig = next((s for s in sigs if len(s[0]) == len(a)), sigs[0])
        out = []
        for (pn, pt, isvar), arg in zip(sig[0], a):
            if isvar and pt['kind'] in VALUE_KINDS:
                out.append(f"ref {arg}")
            elif pt['kind'] in ('int', 'long', 'char', 'byte', 'text'):
                out.append(conv(pt, arg))
            else:
                out.append(arg)
        return f"{name}({', '.join(out)})"

    def builtin(self, p, low):
        p.expect('(')
        if low == 'evaluate':
            target = self.expr_keep(p); p.expect(','); src = self.expr_keep(p); p.expect(')')
            return f"{target} = ALRt.EvalInt({src})"
        if low == 'clear':
            e = self.postfix(p); t = self.lhs_type; p.expect(')')
            k = t['kind'] if t else None
            if k in ('array', 'tb', 'codeunit', 'list'): return f"{e}.Clear()"
            if k == 'text': return f"{e} = \"\""
            return f"{e} = default"
        a = [self.expr_keep(p)]
        while p.accept(','): a.append(self.expr_keep(p))
        p.expect(')')
        if low == 'strlen': return f"ALRt.StrLen({a[0]})"
        if low == 'error': return f"ALRt.Error({a[0]})"

def enums(files):
    out = []
    for f in files:
        s = open(f, encoding='utf-8').read()
        name = cname(re.search(r'enum\s+\d+\s+("[^"]+")', s).group(1))
        vals = re.findall(r'value\((\d+);\s*(\w+)\)', s)
        out.append(f"public enum {name} {{ " + ', '.join(f"{v} = {n}" for n, v in vals) + " }")
    return out

if __name__ == '__main__':
    src = open(sys.argv[1], encoding='utf-8').read()
    count = '--count' in sys.argv
    ens = enums([a for a in sys.argv[2:] if a != '--count'])
    code = Tr(ens, count).run(src)
    print(code.replace("namespace AlGen;", "namespace AlGen;\n" + "\n".join(ens), 1))
