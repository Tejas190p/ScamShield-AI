import re
import unicodedata

# Homoglyph substitution map (common evasions)
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    '@': 'a', '0': 'o', '1': 'i', '!': 'i', '$': 's', '3': 'e'
}

def normalize_text(text: str) -> str:
    """Normalizes input text by unidecoding, removing zero-width characters,
    and mapping common homoglyphs for accurate pattern matching."""
    if not text:
        return ""

    # 1. Strip zero-width spaces and invisible formatting
    text = re.sub(r'[\u200B-\u200D\uFEFF]', '', text)

    # 2. NFKD Unicode normalization
    text = unicodedata.normalize('NFKD', text)

    # 3. Replace known homoglyphs / leetspeak symbols
    cleaned_chars = []
    for char in text:
        cleaned_chars.append(HOMOGLYPH_MAP.get(char, char))
    
    normalized = "".join(cleaned_chars)
    
    # 4. Collapse consecutive whitespace
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized
