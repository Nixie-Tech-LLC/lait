/**
 * A small Markdown parser for issue prose.
 *
 * Descriptions and comments are plain CRDT text in the engine — Markdown is a
 * *reading* convention, not a storage format, so this parses on render and the
 * stored bytes stay exactly what the author typed (and what the CLI prints).
 *
 * Hand-rolled rather than a dependency, deliberately. This bundle is committed
 * into the `lait` binary (`src/serve/assets`), so a full CommonMark engine is
 * dead weight every install carries; and the safety argument wants to be short:
 * the parser emits a typed AST, the renderer builds React elements from it, and
 * no string is ever handed to `innerHTML` — XSS is unrepresentable rather than
 * escaped. The grammar is the subset people actually type into a tracker
 * (Linear's editor shortcuts, roughly): headings, emphasis, code, quotes,
 * lists + checklists, fences, rules, links.
 *
 * What it deliberately does not do: nested lists, tables, images, HTML
 * passthrough. Lines that don't parse stay visible as text — prose must never
 * be eaten by its formatting.
 */

export type Inline =
  | { kind: "text"; text: string }
  | { kind: "code"; text: string }
  | { kind: "strong"; children: Inline[] }
  | { kind: "em"; children: Inline[] }
  | { kind: "strike"; children: Inline[] }
  | { kind: "link"; href: string; children: Inline[] };

export interface ListItem {
  /** `null` = plain bullet; boolean = checklist state. */
  checked: boolean | null;
  children: Inline[];
}

export type Block =
  | { kind: "heading"; level: 1 | 2 | 3 | 4; children: Inline[] }
  /** Text runs keep their soft line breaks — render with `pre-wrap`. */
  | { kind: "paragraph"; children: Inline[] }
  | { kind: "quote"; children: Inline[] }
  | { kind: "code"; lang: string | null; text: string }
  | { kind: "list"; ordered: boolean; items: ListItem[] }
  | { kind: "hr" };

const BULLET = /^\s*([-*+]|\d+[.)])\s+(.*)$/;
const CHECKBOX = /^\[([ xX])\]\s+(.*)$/;
const HEADING = /^(#{1,4})\s+(.*)$/;
const FENCE = /^```(\S*)\s*$/;
const HR = /^(?:-{3,}|_{3,}|\*{3,})\s*$/;
const QUOTE = /^>\s?(.*)$/;

/** Whether this text uses any Markdown at all — a plain paragraph should render
 *  exactly as it always has, without even entering the block path. */
export function looksLikeMarkdown(text: string): boolean {
  return /(^|\n)\s*(#{1,4}\s|[-*+]\s|\d+[.)]\s|>|```)|(\*\*|__|~~|`|\[[^\]]*\]\()/.test(text);
}

export function parseMarkdown(text: string): Block[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  /** Accumulate consecutive lines matching `test`, mapped through `pick`. */
  const run = (test: (l: string) => boolean, pick: (l: string) => string): string[] => {
    const out: string[] = [];
    while (i < lines.length && test(lines[i]!)) {
      out.push(pick(lines[i]!));
      i++;
    }
    return out;
  };

  while (i < lines.length) {
    const line = lines[i]!;

    if (line.trim() === "") {
      i++;
      continue;
    }

    const fence = FENCE.exec(line);
    if (fence) {
      i++;
      const body: string[] = [];
      while (i < lines.length && !FENCE.test(lines[i]!)) {
        body.push(lines[i]!);
        i++;
      }
      i++; // the closing fence (or EOF, which closes it too — never eat prose)
      blocks.push({ kind: "code", lang: fence[1] || null, text: body.join("\n") });
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      i++;
      blocks.push({
        kind: "heading",
        level: heading[1]!.length as 1 | 2 | 3 | 4,
        children: parseInline(heading[2]!),
      });
      continue;
    }

    if (HR.test(line)) {
      i++;
      blocks.push({ kind: "hr" });
      continue;
    }

    if (QUOTE.test(line)) {
      const body = run(
        (l) => QUOTE.test(l),
        (l) => QUOTE.exec(l)![1]!,
      );
      blocks.push({ kind: "quote", children: parseInline(body.join("\n")) });
      continue;
    }

    const bullet = BULLET.exec(line);
    if (bullet) {
      const ordered = /^\d/.test(bullet[1]!);
      const items: ListItem[] = [];
      while (i < lines.length) {
        const m = BULLET.exec(lines[i]!);
        if (!m) break;
        i++;
        const check = CHECKBOX.exec(m[2]!);
        items.push(
          check
            ? { checked: check[1] !== " ", children: parseInline(check[2]!) }
            : { checked: null, children: parseInline(m[2]!) },
        );
      }
      blocks.push({ kind: "list", ordered, items });
      continue;
    }

    // Paragraph: everything until a blank line or a line another block claims.
    const para = run(
      (l) =>
        l.trim() !== "" &&
        !HEADING.test(l) &&
        !FENCE.test(l) &&
        !HR.test(l) &&
        !QUOTE.test(l) &&
        !BULLET.test(l),
      (l) => l,
    );
    blocks.push({ kind: "paragraph", children: parseInline(para.join("\n")) });
  }

  return blocks;
}

/**
 * Inline grammar, longest-marker-first so `**` is never read as two `*`.
 *
 * Each pattern's inner text is parsed recursively except code, whose content is
 * literal by definition. Links only keep `http(s)` hrefs — any other scheme
 * renders as the text it was, which is the safe reading of `javascript:`.
 */
const INLINE: Array<{
  re: RegExp;
  make: (m: RegExpExecArray) => Inline;
}> = [
  { re: /`([^`\n]+)`/, make: (m) => ({ kind: "code", text: m[1]! }) },
  { re: /\*\*([^*\n]+)\*\*/, make: (m) => ({ kind: "strong", children: parseInline(m[1]!) }) },
  { re: /__([^_\n]+)__/, make: (m) => ({ kind: "strong", children: parseInline(m[1]!) }) },
  { re: /~~([^~\n]+)~~/, make: (m) => ({ kind: "strike", children: parseInline(m[1]!) }) },
  { re: /\*([^*\n]+)\*/, make: (m) => ({ kind: "em", children: parseInline(m[1]!) }) },
  // `_`-emphasis must not fire inside snake_case_names: both edges are guarded.
  {
    re: /(?<![\w_])_([^_\n]+)_(?![\w_])/,
    make: (m) => ({ kind: "em", children: parseInline(m[1]!) }),
  },
  {
    re: /\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)/,
    make: (m) => ({ kind: "link", href: m[2]!, children: parseInline(m[1]!) }),
  },
  {
    // Bare URLs, with trailing punctuation left to the sentence it belongs to.
    re: /https?:\/\/[^\s<>()]*[^\s<>().,;:!?'"]/,
    make: (m) => ({ kind: "link", href: m[0], children: [{ kind: "text", text: m[0] }] }),
  },
];

export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let rest = text;
  while (rest.length > 0) {
    // The *earliest* match wins; ties go to the earlier pattern in the table,
    // which is what makes `**` beat `*` (it is listed first and matches at the
    // same index).
    let best: { at: number; m: RegExpExecArray; make: (m: RegExpExecArray) => Inline } | null =
      null;
    for (const { re, make } of INLINE) {
      const m = re.exec(rest);
      if (m && (best === null || m.index < best.at)) best = { at: m.index, m, make };
    }
    if (!best) {
      out.push({ kind: "text", text: rest });
      break;
    }
    if (best.at > 0) out.push({ kind: "text", text: rest.slice(0, best.at) });
    out.push(best.make(best.m));
    rest = rest.slice(best.at + best.m[0].length);
  }
  return out;
}
