"""
Permutation Generator for S3 bucket name generation

Generates bucket name permutations based on company naming patterns.
Uses categorized wordlists and confidence-based pattern generation.
"""

import logging
import re
from typing import Set, List, Dict, Optional
from pathlib import Path


logger = logging.getLogger(__name__)


class PermutationGenerator:
    """
    S3 Bucket Name Permutation Generator

    Generates realistic bucket name permutations using:
    1. Target company identity preservation
    2. Full wordlist coverage across all categories
    3. Confidence-based pattern generation
    4. Real-world naming convention analysis
    """

    def __init__(self):
        """Initialize the permutation generator"""
        # Load all words from wordlist
        self.wordlist_path = Path(__file__).parent / "s3_bucket_wordlist.txt"
        self._load_wordlist()

        # Delimiters in order of frequency in real S3 buckets
        self.DELIMITERS = ['-', '', '_', '.']

    def _load_wordlist(self):
        """Load all words from wordlist file"""
        try:
            with open(self.wordlist_path, 'r') as f:
                self.ALL_WORDS = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith('#')
                ]
        except FileNotFoundError:
            logger.warning(f"Wordlist not found: {self.wordlist_path}, using minimal defaults")
            self.ALL_WORDS = ['backup', 'logs', 'data', 'api', 'web', 'dev', 'prod', 'test']

        logger.info(f"Loaded {len(self.ALL_WORDS)} words for generation")

    def generate(self,
                 target: str,
                 level: str = 'medium',
                 custom_wordlist: Optional[List[str]] = None) -> Set[str]:
        """
        Generate bucket name permutations

        Args:
            target: Base company name or domain
            level: Generation level ('basic', 'medium', 'advanced')
            custom_wordlist: Optional custom word list

        Returns:
            Set of bucket name permutations
        """
        logger.info(f"Generating permutations for '{target}' at level '{level}'")

        # Phase 1: Preserve target identity
        clean_targets = self._preserve_target_identity(target)
        logger.info(f"Target variations: {list(clean_targets)[:3]}...")

        # Phase 2: Generate patterns based on level
        if level == 'basic':
            permutations = self._generate_basic_patterns(clean_targets)
        elif level == 'medium':
            permutations = self._generate_medium_patterns(clean_targets)
        elif level == 'advanced':
            permutations = self._generate_advanced_patterns(clean_targets)
        else:
            raise ValueError(f"Unknown level: {level}")

        # Phase 3: Add custom wordlist if provided
        if custom_wordlist:
            custom_perms = self._combine_with_custom_wordlist(clean_targets, custom_wordlist)
            permutations.update(custom_perms)

        # Phase 4: Filter valid S3 bucket names
        valid_permutations = {
            name for name in permutations
            if self._is_valid_bucket_name(name)
        }

        logger.info(f"Generated {len(valid_permutations)} valid permutations")
        return valid_permutations

    def _preserve_target_identity(self, target: str) -> Set[str]:
        """
        Preserve target company identity

        Ensures the actual company name is never lost in permutations.
        """
        # Clean target while preserving identity
        target = target.lower()

        # Remove common TLDs but keep the company name
        target = re.sub(r'\.(com|org|net|edu|gov|io|co|uk|de|fr|jp|cn)$', '', target)
        target = re.sub(r'^https?://', '', target)
        target = re.sub(r'^www\.', '', target)

        # Replace invalid S3 characters with hyphens
        target = re.sub(r'[^a-z0-9\-]', '-', target)
        target = re.sub(r'-+', '-', target)  # Remove multiple hyphens
        target = target.strip('-')

        # Always preserve the full target name
        variations = {target}

        # Add no-delimiter version for companies like "cognitoapi"
        variations.add(target.replace('-', ''))

        # Add underscore version
        variations.add(target.replace('-', '_'))

        # Only create abbreviations for very long names (>12 chars)
        if len(target) > 12:
            if '-' in target:
                # Multi-word: take meaningful parts
                parts = target.split('-')
                if len(parts) == 2:
                    abbrev = parts[0][:4] + parts[1][:3]
                    if len(abbrev) >= 4:
                        variations.add(abbrev)
            else:
                # Single word: first 8 chars
                variations.add(target[:8])

        return variations

    def _generate_basic_patterns(self, targets: Set[str]) -> Set[str]:
        """
        Generate basic patterns using first 50 words from wordlist

        Patterns:
        - {target}
        - {target}-{word}
        - {word}-{target}
        """
        permutations = set()

        # Include target variations themselves
        permutations.update(targets)

        # Use first 50 words (most common/essential)
        words_to_use = self.ALL_WORDS[:50]

        for target in targets:
            for word in words_to_use:
                # Two most common delimiters
                for delimiter in ['-', '']:
                    permutations.add(f"{target}{delimiter}{word}")
                    permutations.add(f"{word}{delimiter}{target}")

        return permutations

    def _generate_medium_patterns(self, targets: Set[str]) -> Set[str]:
        """
        Generate medium patterns using first 150 words from wordlist

        Patterns:
        - All basic patterns
        - {target}-{word1}-{word2} (two-word combinations)
        - Three delimiters (-, '', _)
        """
        permutations = self._generate_basic_patterns(targets)

        # Use first 150 words
        words_to_use = self.ALL_WORDS[:150]

        for target in targets:
            # Single word patterns with underscore delimiter
            for word in words_to_use:
                permutations.add(f"{target}_{word}")
                permutations.add(f"{word}_{target}")

            # Two-word combinations (top 30 words only for combinations)
            top_words = self.ALL_WORDS[:30]
            for word1 in top_words[:15]:
                for word2 in top_words[15:30]:
                    for delimiter in ['-', '_']:
                        permutations.add(f"{target}{delimiter}{word1}{delimiter}{word2}")

        return permutations

    def _generate_advanced_patterns(self, targets: Set[str]) -> Set[str]:
        """
        Generate advanced patterns using ALL words from wordlist

        Patterns:
        - All medium patterns
        - All single word combinations with all delimiters
        - Three-word combinations
        - All words from all categories
        """
        permutations = self._generate_medium_patterns(targets)

        # Use ALL words
        all_words = self.ALL_WORDS

        for target in targets:
            # Single word patterns with all delimiters
            for word in all_words:
                for delimiter in self.DELIMITERS[:3]:  # -, '', _
                    permutations.add(f"{target}{delimiter}{word}")
                    permutations.add(f"{word}{delimiter}{target}")

            # Two-word combinations (extended)
            # Use first 50 words for combinations to avoid explosion
            combo_words = all_words[:50]
            for i, word1 in enumerate(combo_words):
                for word2 in combo_words[i+1:]:
                    for delimiter in ['-', '_']:
                        permutations.add(f"{target}{delimiter}{word1}{delimiter}{word2}")
                        permutations.add(f"{word1}{delimiter}{target}{delimiter}{word2}")

            # Three-word combinations (top 20 words only)
            top_words = all_words[:20]
            for i, word1 in enumerate(top_words[:10]):
                for word2 in top_words[10:15]:
                    for word3 in top_words[15:20]:
                        permutations.add(f"{target}-{word1}-{word2}-{word3}")

        return permutations

    def _combine_with_custom_wordlist(self, targets: Set[str], wordlist: List[str]) -> Set[str]:
        """Combine targets with custom wordlist"""
        combinations = set()

        for target in targets:
            for word in wordlist:
                word = word.strip().lower()
                if not word:
                    continue

                for delimiter in self.DELIMITERS[:3]:
                    combinations.add(f"{target}{delimiter}{word}")
                    combinations.add(f"{word}{delimiter}{target}")

        return combinations

    def _is_valid_bucket_name(self, name: str) -> bool:
        """
        Validate S3 bucket name according to AWS rules
        """
        # Length check
        if not (3 <= len(name) <= 63):
            return False

        # Must start and end with letter or number
        if not re.match(r'^[a-z0-9].*[a-z0-9]$', name):
            return False

        # Valid characters only
        if not re.match(r'^[a-z0-9\-\.\_]+$', name):
            return False

        # No consecutive dots
        if '..' in name:
            return False

        # No dot-dash combinations
        if '.-' in name or '-.' in name:
            return False

        # No IP address format
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', name):
            return False

        # No xn-- prefix (punycode)
        if name.startswith('xn--'):
            return False

        # No -s3alias suffix
        if name.endswith('-s3alias'):
            return False

        return True

    def get_pattern_confidence(self, bucket_name: str, target: str) -> float:
        """
        Calculate confidence score for a generated bucket name
        """
        target_clean = target.lower().replace('.com', '').replace('-', '').replace('_', '')

        if target_clean in bucket_name:
            if bucket_name.startswith(target_clean):
                return 0.95  # Company-service pattern
            elif bucket_name.endswith(target_clean):
                return 0.90  # Service-company pattern
            else:
                return 0.75  # Complex pattern
        else:
            return 0.40  # Low confidence if target not preserved

    def generate_targeted_permutations(self,
                                       target: str,
                                       focus_areas: List[str]) -> Set[str]:
        """
        Generate permutations focused on specific service areas
        """
        targets = self._preserve_target_identity(target)
        permutations = set()

        for target_var in targets:
            for area in focus_areas:
                area = area.lower()

                # High-confidence patterns for focused areas
                for delimiter in ['-', '']:
                    permutations.add(f"{target_var}{delimiter}{area}")
                    permutations.add(f"{area}{delimiter}{target_var}")

                # With common environments
                for env in ['dev', 'test', 'staging', 'prod']:
                    permutations.add(f"{target_var}-{area}-{env}")
                    permutations.add(f"{target_var}-{env}-{area}")

        return {name for name in permutations if self._is_valid_bucket_name(name)}

    def get_statistics(self) -> Dict[str, int]:
        """Get generation statistics"""
        return {
            'total_words': len(self.ALL_WORDS),
            'delimiters': len(self.DELIMITERS)
        }
