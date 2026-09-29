r"""Semantic normalization: undo shell obfuscation so intent-based detection works where
literal regex fails. Defeats the residual evasions the adaptive red team found
(quote-splitting `r"m"`, variable indirection `${x:-rm}`, backslash splits `s\h`).

A shell would EXECUTE `r"m" -rf /` as `rm -rf /`. So before matching, we canonicalize the
command the way a shell effectively would, then run the existing forbidden patterns against
the de-obfuscated text. It only REMOVES obfuscation, never adds meaning, so it cannot turn a
benign command into a flagged one (tested).
"""
from __future__ import annotations
import re

_VAR_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]*)\}")
_CMD_SUBST = re.compile(r"\$\(([^)]*)\)|`([^`]*)`")


def _deobfuscate_quotes(s: str) -> str:
    """Drop quotes/backslashes used to split a token, keep real quoted strings.

    Rule: a quote is 'splitting' if the character immediately before it is a word char
    (so it's glued to a token). A real quoted argument is preceded by a space or operator
    (e.g. echo "hi") or contains a space. We scan char by char and drop a quote only when
    the previous kept char is a word char AND the quoted run has no space in it.
    """
    out = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch in "\"'":
            prev_word = bool(out) and (out[-1].isalnum() or out[-1] in "_-/.")
            # find matching close
            j = s.find(ch, i + 1)
            if prev_word and j != -1 and " " not in s[i + 1:j]:
                # glued, spaceless quoted run -> it's a split; drop both quotes, keep inner
                out.append(s[i + 1:j])
                i = j + 1
                continue
            # otherwise: a real quoted string (or unmatched) -> keep as-is up to close
            if j != -1:
                out.append(s[i:j + 1]); i = j + 1; continue
            out.append(ch); i += 1; continue
        if ch == "\\" and 0 < i < n - 1 and s[i - 1].isalnum() and s[i + 1].isalnum():
            i += 1; continue          # backslash between word chars: drop it
        out.append(ch); i += 1
    return "".join(out)


def _ansi_c_decode(s: str) -> str:
    r"""Decode $'...' ANSI-C quoting (\xHH hex, \NNN octal) the way a shell would, so
    $'\x72\x6d' becomes rm before pattern matching."""
    import re as _re
    def repl(m):
        body = m.group(1)
        body = _re.sub(r"\\x([0-9a-fA-F]{2})", lambda h: chr(int(h.group(1), 16)), body)
        body = _re.sub(r"\\([0-7]{1,3})", lambda o: chr(int(o.group(1), 8)), body)
        return body
    return _re.sub(r"\$'([^']*)'", repl, s)

def normalize(cmd: str) -> str:
    """Return a de-obfuscated form of `cmd` for intent matching."""
    if not cmd:
        return cmd
    s = cmd
    prev = None
    while prev != s:                  # expand ${x:-rm} -> rm (nested-safe)
        prev = s
        s = _VAR_DEFAULT.sub(r"\1", s)
    s = _ansi_c_decode(s)
    s = _CMD_SUBST.sub(lambda m: (m.group(1) or m.group(2) or ""), s)
    s = s.replace("\\\n", "").replace("\u00a0", " ")
    s = _deobfuscate_quotes(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s
