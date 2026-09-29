# strikerr/apps/analyzer/lexicon/lexicon_engine.py
import os
import json
from collections import deque
from typing import Dict, List, Tuple, Any

try:
    import ahocorasick
    HAS_C_AHOCORASICK = True
except ImportError:
    HAS_C_AHOCORASICK = False

class PurePythonAhoCorasick:
    """Pure-Python Aho-Corasick Automaton for high-throughput string matching fallback."""

    def __init__(self):
        self.trie = [{}]  # Node 0 is root: mapping char -> next node index
        self.output = [[]]  # Node index -> list of payloads
        self.fail = [0]  # Failure links
        self.is_finalized = False

    def add_word(self, word: str, payload: Any):
        if self.is_finalized:
            raise RuntimeError("Cannot add words after automaton is finalized")
        node = 0
        for char in word:
            if char not in self.trie[node]:
                next_node = len(self.trie)
                self.trie.append({})
                self.output.append([])
                self.fail.append(0)
                self.trie[node][char] = next_node
            node = self.trie[node][char]
        self.output[node].append(payload)

    def make_automaton(self):
        queue = deque()
        # Initialize depth 1 nodes
        for char, next_node in self.trie[0].items():
            self.fail[next_node] = 0
            queue.append(next_node)

        # BFS to construct failure links
        while queue:
            curr = queue.popleft()
            for char, next_node in self.trie[curr].items():
                queue.append(next_node)
                f = self.fail[curr]
                while f > 0 and char not in self.trie[f]:
                    f = self.fail[f]
                if char in self.trie[f]:
                    self.fail[next_node] = self.trie[f][char]
                else:
                    self.fail[next_node] = 0
                # Merge outputs
                self.output[next_node].extend(self.output[self.fail[next_node]])

        self.is_finalized = True

    def iter(self, text: str):
        """Yields (end_index, payload) tuples for all matches found in text."""
        node = 0
        for idx, char in enumerate(text):
            while node > 0 and char not in self.trie[node]:
                node = self.fail[node]
            if char in self.trie[node]:
                node = self.trie[node][char]
            else:
                node = 0
            if self.output[node]:
                for payload in self.output[node]:
                    yield (idx, payload)

class LocalizedLexiconEngine:
    """Manages Indonesian threat lexicons and performs rapid O(n) multi-keyword matching."""

    def __init__(self):
        self.automaton = None
        self.keyword_metadata = {}
        self._load_dictionaries()

    def _load_dictionaries(self):
        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        
        if HAS_C_AHOCORASICK:
            self.automaton = ahocorasick.Automaton()
        else:
            self.automaton = PurePythonAhoCorasick()

        dict_files = ['judol_id.json', 'scam_id.json']
        for fname in dict_files:
            fpath = os.path.join(data_dir, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                category = data.get('category', 'UNKNOWN')
                for item in data.get('keywords', []):
                    term = item['term'].strip().lower()
                    weight = item.get('weight', 5)
                    self.keyword_metadata[term] = {
                        'category': category,
                        'weight': weight
                    }
                    self.automaton.add_word(term, (category, term, weight))

        self.automaton.make_automaton()

    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scans arbitrary text and returns matched threat terms, counts, and category scores."""
        if not text:
            return {
                'matched_keywords': [],
                'judol_score': 0,
                'scam_score': 0,
                'total_weight': 0
            }

        text_lower = text.lower()
        matched = {}
        judol_score = 0
        scam_score = 0

        # Query automaton
        for end_idx, payload in self.automaton.iter(text_lower):
            category, term, weight = payload
            if term not in matched:
                matched[term] = {
                    'category': category,
                    'term': term,
                    'count': 1,
                    'weight': weight
                }
                if category == 'ONLINE_GAMBLING':
                    judol_score += weight
                elif category == 'FINANCIAL_SCAM':
                    scam_score += weight
            else:
                matched[term]['count'] += 1

        total_weight = judol_score + scam_score

        return {
            'matched_keywords': list(matched.values()),
            'judol_score': judol_score,
            'scam_score': scam_score,
            'total_weight': total_weight
        }

# Global singleton instance
GLOBAL_LEXICON_ENGINE = LocalizedLexiconEngine()
