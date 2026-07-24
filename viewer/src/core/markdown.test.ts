import { describe, expect, it } from "vitest";

import { looksLikeMarkdown, parseInline, parseMarkdown, type Block } from "./markdown";

describe("looksLikeMarkdown", () => {
  it("stays out of plain prose", () => {
    expect(looksLikeMarkdown("just a sentence.")).toBe(false);
    expect(looksLikeMarkdown("two lines\nof plain text")).toBe(false);
    // A lone asterisk mid-sentence is arithmetic, not emphasis.
    expect(looksLikeMarkdown("2 * 3 = 6")).toBe(false);
  });

  it("wakes up for the marks people actually type", () => {
    expect(looksLikeMarkdown("# heading")).toBe(true);
    expect(looksLikeMarkdown("- a list")).toBe(true);
    expect(looksLikeMarkdown("with `code` inline")).toBe(true);
    expect(looksLikeMarkdown("**bold** claim")).toBe(true);
    expect(looksLikeMarkdown("see [docs](https://example.com)")).toBe(true);
  });
});

describe("blocks", () => {
  it("parses headings h1–h4 and leaves ##### as prose", () => {
    expect(parseMarkdown("## Title")[0]).toMatchObject({ kind: "heading", level: 2 });
    expect(parseMarkdown("##### deep")[0]!.kind).toBe("paragraph");
  });

  it("keeps a fence's body verbatim, and EOF closes an unclosed fence", () => {
    const [block] = parseMarkdown("```rust\nlet x = **not bold**;\n```");
    expect(block).toMatchObject({ kind: "code", lang: "rust", text: "let x = **not bold**;" });
    const [open] = parseMarkdown("```\ndangling");
    expect(open).toMatchObject({ kind: "code", text: "dangling" });
  });

  it("groups consecutive bullets into one list, and reads checklists", () => {
    const [list] = parseMarkdown("- [x] done\n- [ ] not yet\n- plain") as [
      Extract<Block, { kind: "list" }>,
    ];
    expect(list.kind).toBe("list");
    expect(list.items.map((i) => i.checked)).toEqual([true, false, null]);
  });

  it("distinguishes ordered from unordered lists", () => {
    expect(parseMarkdown("1. a\n2. b")[0]).toMatchObject({ kind: "list", ordered: true });
    expect(parseMarkdown("* a")[0]).toMatchObject({ kind: "list", ordered: false });
  });

  it("merges consecutive quote lines into one quote", () => {
    const blocks = parseMarkdown("> first\n> second");
    expect(blocks).toHaveLength(1);
    expect(blocks[0]!.kind).toBe("quote");
  });

  it("keeps soft line breaks inside a paragraph", () => {
    const [p] = parseMarkdown("line one\nline two") as [Extract<Block, { kind: "paragraph" }>];
    expect(p.children).toEqual([{ kind: "text", text: "line one\nline two" }]);
  });

  it("reads a rule, and blank lines split paragraphs", () => {
    const kinds = parseMarkdown("a\n\n---\n\nb").map((b) => b.kind);
    expect(kinds).toEqual(["paragraph", "hr", "paragraph"]);
  });
});

describe("inlines", () => {
  it("gives ** precedence over *", () => {
    expect(parseInline("**bold**")[0]!.kind).toBe("strong");
  });

  it("keeps code content literal", () => {
    expect(parseInline("`**x**`")).toEqual([{ kind: "code", text: "**x**" }]);
  });

  it("does not read snake_case as emphasis", () => {
    expect(parseInline("a snake_case_name here")).toEqual([
      { kind: "text", text: "a snake_case_name here" },
    ]);
  });

  it("links only http(s); other schemes stay text", () => {
    expect(parseInline("[x](https://a.b)")[0]).toMatchObject({ kind: "link", href: "https://a.b" });
    // `javascript:` must never become an href — the whole safety argument.
    const hostile = parseInline("[x](javascript:alert(1))");
    expect(hostile.every((i) => i.kind !== "link")).toBe(true);
  });

  it("autolinks bare URLs without eating trailing punctuation", () => {
    const parts = parseInline("see https://example.com/a, ok");
    expect(parts[1]).toMatchObject({ kind: "link", href: "https://example.com/a" });
    expect(parts[2]).toEqual({ kind: "text", text: ", ok" });
  });
});
