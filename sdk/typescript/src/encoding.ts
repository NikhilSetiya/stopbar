// Encoding detector (CS-183, LLD §8.2): flags encoded content in untrusted
// input so the session carries the `decoded` label.
//
// An injected instruction hidden in base64, hex, Morse, ROT-n or zero-width
// characters reads as noise to a human reviewer but not to the model, which
// decodes it (the Grok/Bankr pattern, corpus CS-2026-0001). The detector only
// adds a label, and labels only restrict, so a miss never loosens anything.
//
// To keep false positives low on ordinary content (addresses, tx hashes,
// calldata, ids, emoji), base64 and hex count only when they decode to readable
// text, Morse needs a run of real codes, and ROT-n needs a segment that is not
// English as written but is under some rotation. A line-for-line port of
// sdk/python/stopbar/encoding.py; sdk/testdata/encodings.json holds the
// fixtures both SDKs' tests must agree on.

export const KINDS = ["base64", "hex", "morse", "rot", "zero_width"] as const;
export type Encoding = (typeof KINDS)[number];

// Emoji joined by ZWJ (family, flags), a leading BOM and ZWNJ inside non-Latin
// words are legitimate; they are removed before looking for hidden characters.
const EMOJI_ZWJ = /([\u{2600}-\u{27bf}\u{1f000}-\u{1faff}]\u{fe0f}?)\u{200d}(?=[\u{2600}-\u{27bf}\u{1f000}-\u{1faff}])/gu;
const ZWNJ_IN_WORD = /(?<=[^\x00-\x7f])\u{200c}(?=[^\x00-\x7f])/gu;
const ZERO_WIDTH = /[\u{200b}-\u{200d}\u{2060}-\u{2064}\u{180e}\u{feff}\u{e0000}-\u{e007f}]/u;

const B64 = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])/g;
const HEX = /(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{16,}|(?:[0-9a-fA-F]{2}[ :]){7,}[0-9a-fA-F]{2})(?![0-9A-Za-z])/g;

const MORSE: Record<string, string> = {
  ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h",
  "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p",
  "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
  "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
  ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
};

// Common English words (3+ letters) plus the vocabulary of wallet-draining
// instructions; ROT-n is flagged when a rotation turns a non-English segment
// into mostly these. Keep in step with the Python WORDS.
const WORDS = new Set(`
the and for are but not you all any can her was one our out has him his how new now old see two way who did
its let put say she too use this that with have from they will would there their what about which when make
like time just know take into your some could them than then look only come over think also back after work
first well even want because these give most here been were said each more other many such very must should
please send transfer ignore previous instructions instruction wallet token tokens funds money address
immediately balance approve execute system prompt user assistant command following below above private key
keys secret password admin account pay payment eth usdc bitcoin crypto swap buy sell reply tell everything
contract call new rules forget disregard
`.split(/\s+/).filter(Boolean));

/** The encodings found in text, in KINDS order. */
export function detectEncodings(text: string): Encoding[] {
  const found = new Set<Encoding>();
  const visible = (text.startsWith("\u{feff}") ? text.slice(1) : text).replace(EMOJI_ZWJ, "$1").replace(ZWNJ_IN_WORD, "");
  if (ZERO_WIDTH.test(visible)) found.add("zero_width");
  for (const m of text.matchAll(B64)) {
    const s = m[0].replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
    if (s.length % 4 === 1) continue;
    if (readable(Buffer.from(s, "base64"))) {
      found.add("base64");
      break;
    }
  }
  for (const m of text.matchAll(HEX)) {
    const h = m[0].replace(/^0x/, "").replace(/[ :]/g, "");
    if (readable(Buffer.from(h.slice(0, h.length - (h.length % 2)), "hex"))) {
      found.add("hex");
      break;
    }
  }
  if (morse(text)) found.add("morse");
  if (rot(text)) found.add("rot");
  return KINDS.filter((k) => found.has(k));
}

/** Decoded bytes that are text: printable ASCII, mostly letters, and not one
 * repeated byte (test addresses like 0x5555... decode to "UUUU"). */
function readable(raw: Uint8Array): boolean {
  const n = raw.length;
  if (n < 6 || new Set(raw).size < 5) return false;
  let printable = 0;
  let letters = 0;
  for (const b of raw) {
    if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) printable++;
    if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)) letters++;
  }
  return printable >= 0.95 * n && letters >= 0.5 * n;
}

/** A run of at least five valid Morse codes, using both dots and dashes. */
function morse(text: string): boolean {
  const norm = text.replace(/[\u{00b7}\u{2022}]/gu, ".").replace(/[\u{2013}\u{2014}\u{2212}_]/gu, "-").replace(/[/|]/g, " / ");
  let run: string[] = [];
  for (const tok of [...norm.split(/\s+/).filter(Boolean), ""]) {
    if (tok in MORSE) run.push(tok);
    else if (tok === "/") continue;
    else {
      const joined = run.join("");
      if (run.length >= 5 && joined.includes(".") && joined.includes("-")) return true;
      run = [];
    }
  }
  return false;
}

/** A segment of 4+ distinct words that is not English as written but is
 * under some rotation n in 1..25 (ROT13 being the usual one). */
function rot(text: string): boolean {
  for (const seg of text.split(/[\n\r.!?;:"()[\]{}<>]+/)) {
    const words = [...new Set((seg.match(/[A-Za-z]+/g) ?? []).filter((w) => w.length >= 3).map((w) => w.toLowerCase()))];
    if (words.length < 4 || hits(words) >= 0.2 * words.length) continue;
    for (let n = 1; n < 26; n++) {
      const rotated = words.map((w) => String.fromCharCode(...[...w].map((c) => ((c.charCodeAt(0) - 97 + n) % 26) + 97)));
      const h = hits(rotated);
      if (h >= 3 && h >= 0.5 * words.length) return true;
    }
  }
  return false;
}

function hits(words: string[]): number {
  return words.filter((w) => WORDS.has(w)).length;
}
