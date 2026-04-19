import re
import unicodedata

URDU_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")
ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
SEPARATORS_RE = re.compile(r"[\s\-\._:/,؛،()\[\]{}|\\]+")
WHITESPACE_RE = re.compile(r"\s+")

LEET_TABLE = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
    }
)

PUNCT_TRANSLATION = str.maketrans(
    {
        "’": "'",
        "‘": "'",
        "`": "'",
        "“": '"',
        "”": '"',
        "–": "-",
        "—": "-",
        "۔": ".",
        "،": ",",
        "؛": ";",
    }
)

ROMAN_URDU_HINTS = {
    "mera",
    "naam",
    "mobile",
    "raabta",
    "account",
    "cnic",
    "khata",
    "paidaish",
    "batao",
    "kya",
}

URDU_TO_LATIN = {
    "ا": "a",
    "آ": "aa",
    "ب": "b",
    "پ": "p",
    "ت": "t",
    "ٹ": "t",
    "ث": "s",
    "ج": "j",
    "چ": "ch",
    "ح": "h",
    "خ": "kh",
    "د": "d",
    "ڈ": "d",
    "ذ": "z",
    "ر": "r",
    "ڑ": "r",
    "ز": "z",
    "ژ": "zh",
    "س": "s",
    "ش": "sh",
    "ص": "s",
    "ض": "z",
    "ط": "t",
    "ظ": "z",
    "ع": "a",
    "غ": "gh",
    "ف": "f",
    "ق": "q",
    "ک": "k",
    "گ": "g",
    "ل": "l",
    "م": "m",
    "ن": "n",
    "و": "w",
    "ہ": "h",
    "ھ": "h",
    "ء": "",
    "ی": "i",
    "ے": "e",
    "ئ": "i",
    "ں": "n",
}


def normalize_for_detection(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.translate(URDU_DIGITS).translate(ARABIC_DIGITS)
    normalized = normalized.translate(PUNCT_TRANSLATION)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    return normalized


def collapse_whitespace(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def transliterate_urdu_to_latin(text: str) -> str:
    out: list[str] = []
    for char in text:
        out.append(URDU_TO_LATIN.get(char, char))
    return "".join(out)


def canonicalize_sensitive(value: str) -> str:
    normalized = normalize_for_detection(value)
    normalized = transliterate_urdu_to_latin(normalized)
    normalized = normalized.lower().translate(LEET_TABLE)
    normalized = re.sub(r"\b([a-z]{2,})['’]s\b", r"\1", normalized)
    normalized = SEPARATORS_RE.sub("", normalized)
    return normalized


def contains_roman_urdu(text: str) -> bool:
    lower_text = normalize_for_detection(text).lower()
    return any(hint in lower_text for hint in ROMAN_URDU_HINTS)


def masked_excerpt(value: str) -> str:
    cleaned = collapse_whitespace(value)
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    return f"{cleaned[:2]}{'*' * max(2, len(cleaned) - 4)}{cleaned[-2:]}"
