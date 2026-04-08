#!/usr/bin/env python3
"""
Generate a Spanish translation .po file for the WP.org plugin readme by:

1. Downloading the official GlotPress template (with empty msgstrs) from
   translate.wordpress.org. This is our source of truth for which strings
   exist in the readme and how GlotPress segments them.
2. For each English msgid in the template, finding the exact text in
   readme.txt to determine its line range.
3. Extracting the equivalent block from readme-es.txt at the same line
   range, which becomes the Spanish msgstr.
4. Writing the resulting .po file.

This approach guarantees that the segmentation matches GlotPress exactly,
so the import will populate every existing GlotPress entry. New strings
added to readme.txt that GlotPress hasn't synced yet will be reported and
need manual handling on the next sync.

Requirements:
- readme.txt and readme-es.txt MUST be line-aligned: same number of lines,
  same blank-line positions, same section headers in same positions.

Usage:
  python3 bin/generate-readme-po.py <english.txt> <spanish.txt> <output.po> [--template <path>]

Examples:
  # Auto-download template from translate.wordpress.org
  python3 bin/generate-readme-po.py readme.txt readme-es.txt /tmp/readme-es.po

  # Use a local template (e.g. cached in CI)
  python3 bin/generate-readme-po.py readme.txt readme-es.txt /tmp/readme-es.po \\
    --template /tmp/glotpress-template.po
"""
import sys
import urllib.request
from datetime import datetime, timezone

GLOTPRESS_TEMPLATE_URL = (
    'https://translate.wordpress.org/projects/wp-plugins/'
    'es-football-bypass-for-cloudflare/stable-readme/es/default/'
    'export-translations/?format=po'
)


# ────────────────────────── PO parsing ──────────────────────────


def parse_po_entries(content):
    """Parse a .po file content and return a list of dicts with keys:
    {comments: [str], msgid: str, msgstr: str}.
    Skips the header (entry with empty msgid).
    Handles multi-line msgid/msgstr correctly.
    """
    entries = []
    lines = content.split('\n')
    i = 0
    n = len(lines)

    def unescape(s):
        return s.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')

    while i < n:
        comments = []
        # Skip blank lines
        while i < n and lines[i].strip() == '':
            i += 1
        # Collect comment lines
        while i < n and lines[i].startswith('#'):
            comments.append(lines[i])
            i += 1
        if i >= n:
            break
        # Parse msgid
        if not lines[i].startswith('msgid '):
            i += 1
            continue
        msgid_parts = []
        # First line: msgid "..."
        first = lines[i][len('msgid '):].strip()
        if first.startswith('"') and first.endswith('"'):
            msgid_parts.append(first[1:-1])
        i += 1
        # Continuation lines
        while i < n and lines[i].startswith('"') and lines[i].rstrip().endswith('"'):
            msgid_parts.append(lines[i].strip()[1:-1])
            i += 1
        msgid = unescape(''.join(msgid_parts))

        # Parse msgstr
        if i >= n or not lines[i].startswith('msgstr '):
            continue
        msgstr_parts = []
        first = lines[i][len('msgstr '):].strip()
        if first.startswith('"') and first.endswith('"'):
            msgstr_parts.append(first[1:-1])
        i += 1
        while i < n and lines[i].startswith('"') and lines[i].rstrip().endswith('"'):
            msgstr_parts.append(lines[i].strip()[1:-1])
            i += 1
        msgstr = unescape(''.join(msgstr_parts))

        if msgid:  # Skip header (empty msgid)
            entries.append({
                'comments': comments,
                'msgid': msgid,
                'msgstr': msgstr,
            })

    return entries


# ────────────────────── readme alignment ──────────────────────


def decode_html_entities(s):
    """Decode the HTML entities GlotPress uses in msgid (mainly &gt; &lt; &amp;)."""
    return (
        s.replace('&gt;', '>')
         .replace('&lt;', '<')
         .replace('&amp;', '&')
    )


def backticks_to_code(s):
    """Convert WordPress readme backtick code spans to GlotPress <code>...</code>.
    GlotPress's readme parser renders `foo` as <code>foo</code> in msgid."""
    out = []
    open_tag = True
    for ch in s:
        if ch == '`':
            out.append('<code>' if open_tag else '</code>')
            open_tag = not open_tag
        else:
            out.append(ch)
    return ''.join(out)


def normalize_line(line):
    """Normalize a readme line for matching: strip whitespace, leading
    list markers (- / *), numbered markers (1. ), and equals headers
    (= / == / ===). Also converts backtick code spans to <code> tags so
    they match the GlotPress msgid format."""
    s = line.strip()
    # Strip equals header markers (= Foo =, == Foo ==, === Foo ===)
    if s.startswith('=') and s.endswith('=') and ' ' in s:
        # Count leading equals
        n = 0
        while n < len(s) and s[n] == '=':
            n += 1
        # Must have matching trailing
        if s.endswith('=' * n) and len(s) > 2 * n:
            inner = s[n:-n].strip()
            if inner:
                s = inner
    # Strip list markers
    if s.startswith('- ') or s.startswith('* '):
        s = s[2:]
    # Strip numbered markers like "1. ", "12. "
    elif len(s) >= 3 and s[0].isdigit():
        j = 0
        while j < len(s) and s[j].isdigit():
            j += 1
        if j > 0 and j + 1 < len(s) and s[j] == '.' and s[j+1] == ' ':
            s = s[j+2:]
    # Convert backticks to <code> spans (so we match GlotPress's HTML form)
    s = backticks_to_code(s)
    return s


def find_msgid_line_range(msgid, readme_lines):
    """Locate an msgid in readme_lines. Returns a list of line indices that
    correspond to this msgid in the readme, or None.

    Strategies tried in order:
      1. Multi-line block match (each line of msgid maps to a consecutive
         readme line, after normalising both sides).
      2. Single-line direct match against a normalized readme line.
      3. Wrapped paragraph: collect consecutive non-empty readme lines and
         join with spaces, test if it matches the msgid.
    """
    msgid = decode_html_entities(msgid).strip()
    msgid_lines = msgid.split('\n')

    # 1) Multi-line block match
    if len(msgid_lines) > 1:
        for i in range(len(readme_lines) - len(msgid_lines) + 1):
            ok = True
            for k in range(len(msgid_lines)):
                target = msgid_lines[k].strip()
                # The msgid line may itself contain a leading "- " for bulleted
                # items inside a multi-line block. Compare via normalised forms
                # on both sides so we accept either case consistently.
                candidate_norm = normalize_line(readme_lines[i + k])
                target_norm = normalize_line(target)
                if candidate_norm != target_norm:
                    ok = False
                    break
            if ok:
                return list(range(i, i + len(msgid_lines)))

    # 2) Single-line direct match
    for i, line in enumerate(readme_lines):
        if normalize_line(line) == msgid:
            return [i]

    # 3) Wrapped paragraph match: join consecutive non-empty lines
    for i in range(len(readme_lines)):
        if not readme_lines[i].strip():
            continue
        joined = []
        for k in range(min(20, len(readme_lines) - i)):
            line = readme_lines[i + k].strip()
            if not line:
                break
            joined.append(line)
            if ' '.join(joined) == msgid:
                return list(range(i, i + k + 1))

    return None


def extract_spanish(line_indices, es_lines, msgid):
    """Given line indices from the English readme, extract the equivalent
    block from the Spanish readme. Apply the same normalisation that was
    used to match the msgid, but preserve the original msgid's structural
    markers (newlines, bullet/numbered prefixes) in the output."""
    msgid = decode_html_entities(msgid)
    msgid_lines = msgid.split('\n')

    if len(msgid_lines) > 1:
        # Multi-line: each spanish line corresponds to one msgid line
        out = []
        for k, idx in enumerate(line_indices):
            spanish_norm = normalize_line(es_lines[idx])
            # Preserve the same prefix the original msgid line had
            target = msgid_lines[k]
            if target.startswith('- '):
                spanish_norm = '- ' + spanish_norm
            elif target.startswith('* '):
                spanish_norm = '* ' + spanish_norm
            out.append(spanish_norm)
        return '\n'.join(out)

    if len(line_indices) == 1:
        return normalize_line(es_lines[line_indices[0]])

    # Wrapped paragraph: join the equivalent lines with spaces
    return ' '.join(es_lines[idx].strip() for idx in line_indices)


# ────────────────────────── PO writing ──────────────────────────


def escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def serialize_msg(s, key):
    if not s:
        return f'{key} ""'
    return f'{key} "{escape(s)}"'


def write_po(entries, output_path, slug):
    out = []
    out.append(
        f'# Translation of Plugins - ES Football Bypass for Cloudflare - '
        f'Stable Readme (latest release) in Spanish (Spain)'
    )
    out.append('# Auto-generated from readme.txt and readme-es.txt by bin/generate-readme-po.py')
    out.append('# Re-run the script after editing either readme to refresh.')
    out.append('msgid ""')
    out.append('msgstr ""')
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M+0000')
    out.append(f'"PO-Revision-Date: {now}\\n"')
    out.append('"Last-Translator: David Carrero Fernandez-Baillo <david@carrero.es>\\n"')
    out.append('"Language-Team: Spanish (Spain)\\n"')
    out.append('"MIME-Version: 1.0\\n"')
    out.append('"Content-Type: text/plain; charset=UTF-8\\n"')
    out.append('"Content-Transfer-Encoding: 8bit\\n"')
    out.append('"Plural-Forms: nplurals=2; plural=n != 1;\\n"')
    out.append('"X-Generator: bin/generate-readme-po.py\\n"')
    out.append('"Language: es\\n"')
    out.append(
        f'"Project-Id-Version: Plugins - {slug} - Stable Readme '
        f'(latest release)\\n"'
    )

    for entry in entries:
        out.append('')
        for c in entry['comments']:
            out.append(c)
        out.append(serialize_msg(entry['msgid'], 'msgid'))
        out.append(serialize_msg(entry['msgstr'], 'msgstr'))

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')


# ────────────────────────── main ──────────────────────────


def fetch_template():
    sys.stderr.write(f'Downloading GlotPress template from {GLOTPRESS_TEMPLATE_URL}\n')
    with urllib.request.urlopen(GLOTPRESS_TEMPLATE_URL, timeout=30) as resp:
        return resp.read().decode('utf-8')


def main():
    args = sys.argv[1:]
    template_path = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == '--template':
            template_path = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    if len(positional) != 3:
        sys.stderr.write(__doc__)
        raise SystemExit(1)

    en_path, es_path, out_path = positional

    with open(en_path, 'r', encoding='utf-8') as f:
        en_content = f.read()
    with open(es_path, 'r', encoding='utf-8') as f:
        es_content = f.read()

    en_lines = en_content.split('\n')
    es_lines = es_content.split('\n')

    if len(en_lines) != len(es_lines):
        sys.stderr.write(
            f'WARNING: line count mismatch: {en_path}={len(en_lines)} '
            f'vs {es_path}={len(es_lines)}. Alignment may fail for some strings.\n'
        )

    if template_path:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
    else:
        template_content = fetch_template()

    template_entries = parse_po_entries(template_content)
    sys.stderr.write(f'Template entries: {len(template_entries)}\n')

    matched = 0
    not_found = []
    output_entries = []

    for entry in template_entries:
        msgid = entry['msgid']
        line_range = find_msgid_line_range(msgid, en_lines)
        if line_range is None:
            not_found.append(msgid)
            output_entries.append(entry)  # keep with empty msgstr
            continue
        spanish = extract_spanish(line_range, es_lines, msgid)
        output_entries.append({
            'comments': entry['comments'],
            'msgid': msgid,
            'msgstr': spanish,
        })
        matched += 1

    write_po(output_entries, out_path, slug='es-football-bypass-for-cloudflare')

    sys.stderr.write(
        f'Matched {matched}/{len(template_entries)} entries. '
        f'Wrote {out_path}\n'
    )

    if not_found:
        sys.stderr.write(
            f'\nWARNING: {len(not_found)} msgid(s) from the GlotPress template '
            f'could not be located in {en_path}:\n'
        )
        for msgid in not_found[:10]:
            preview = msgid[:80].replace('\n', ' ')
            sys.stderr.write(f'  - {preview}\n')
        if len(not_found) > 10:
            sys.stderr.write(f'  (... and {len(not_found) - 10} more)\n')
        sys.stderr.write(
            '\nThese entries are kept with an empty msgstr. They likely correspond '
            'to readme content that has been removed or modified since the GlotPress '
            'template was generated. The next GlotPress sync will resolve them.\n'
        )

    if matched == 0:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
