"""
Wordlist Manager - Intelligent wordlist handling and generation

This module provides comprehensive wordlist management including:
- Built-in wordlists from analyzed tools
- Custom wordlist loading and validation
- Dynamic wordlist generation
- Wordlist optimization and filtering
"""

import logging
from typing import List, Optional, Dict
from pathlib import Path


logger = logging.getLogger(__name__)


class WordlistManager:
    """
    Manages wordlists for S3 bucket enumeration

    Features:
    - Built-in comprehensive wordlists
    - Custom wordlist loading and validation
    - Dynamic wordlist generation based on context
    - Wordlist optimization and filtering
    """

    # Built-in wordlist from analyzed tools (s3enum, cloud_enum, lazys3)
    BUILTIN_WORDLIST = [
        # Basic services
        'api', 'app', 'application', 'service', 'web', 'website', 'www',
        'cdn', 'static', 'assets', 'media', 'images', 'files', 'uploads',
        'data', 'database', 'db', 'backup', 'backups', 'archive', 'archives',
        'logs', 'log', 'logging', 'audit', 'reports', 'analytics', 'metrics',
        'cache', 'tmp', 'temp', 'temporary', 'storage', 'store', 'repo',
        'config', 'configuration', 'settings', 'secrets', 'keys', 'certs',

        # Development environments
        'dev', 'development', 'devel', 'develop', 'test', 'testing', 'tst',
        'stage', 'staging', 'stg', 'prod', 'production', 'prd', 'live',
        'demo', 'sandbox', 'sb', 'qa', 'qc', 'uat', 'acceptance', 'preview',

        # Departments
        'engineering', 'eng', 'tech', 'it', 'infra', 'infrastructure',
        'marketing', 'mkt', 'sales', 'business', 'biz', 'finance', 'fin',
        'hr', 'people', 'legal', 'compliance', 'security', 'sec', 'infosec',
        'operations', 'ops', 'devops', 'sre', 'support', 'help', 'customer',
        'product', 'design', 'ux', 'ui', 'research', 'analytics', 'data',

        # Technologies
        'aws', 'amazon', 's3', 'ec2', 'lambda', 'rds', 'dynamodb', 'sqs',
        'docker', 'kubernetes', 'k8s', 'helm', 'terraform', 'ansible',
        'jenkins', 'ci', 'cd', 'github', 'gitlab', 'git', 'svn', 'bitbucket',
        'node', 'nodejs', 'npm', 'react', 'angular', 'vue', 'javascript',
        'python', 'java', 'golang', 'php', 'ruby', 'dotnet', 'scala',
        'mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'kafka',
        'nginx', 'apache', 'haproxy', 'cloudflare', 'akamai', 'fastly',

        # Business functions
        'admin', 'administration', 'management', 'portal', 'dashboard',
        'billing', 'payment', 'checkout', 'cart', 'order', 'invoice',
        'customer', 'client', 'user', 'account', 'profile', 'settings',
        'notification', 'email', 'sms', 'push', 'webhook', 'integration',
        'sync', 'import', 'export', 'etl', 'pipeline', 'workflow',

        # Content types
        'documents', 'docs', 'files', 'attachments', 'downloads',
        'images', 'photos', 'pictures', 'gallery', 'thumbnails',
        'videos', 'audio', 'music', 'podcasts', 'streaming',
        'fonts', 'css', 'js', 'assets', 'resources', 'libraries',

        # Security and compliance
        'security', 'secure', 'private', 'internal', 'confidential',
        'encrypted', 'ssl', 'tls', 'cert', 'certificate', 'key', 'keys',
        'audit', 'compliance', 'gdpr', 'hipaa', 'sox', 'pci', 'iso',
        'backup', 'disaster', 'recovery', 'restore', 'snapshot',

        # Common patterns
        'public', 'private', 'shared', 'common', 'global', 'local',
        'master', 'main', 'primary', 'secondary', 'backup', 'mirror',
        'old', 'new', 'legacy', 'current', 'latest', 'beta', 'alpha',
        'stable', 'release', 'candidate', 'rc', 'hotfix', 'patch',

        # Versions and numbers
        'v1', 'v2', 'v3', 'v4', 'v5', 'version1', 'version2', 'version3',
        '1', '2', '3', '4', '5', '01', '02', '03', '04', '05',
        '2020', '2021', '2022', '2023', '2024', '2025',

        # Regional and geographic
        'us', 'usa', 'america', 'north', 'south', 'east', 'west',
        'eu', 'europe', 'asia', 'apac', 'emea', 'global', 'worldwide',
        'region', 'regional', 'zone', 'datacenter', 'dc',

        # Industry specific
        'finance', 'financial', 'bank', 'banking', 'fintech', 'payment',
        'healthcare', 'health', 'medical', 'hospital', 'clinic',
        'retail', 'ecommerce', 'shop', 'store', 'marketplace',
        'education', 'school', 'university', 'student', 'course',
        'media', 'news', 'blog', 'content', 'publishing', 'magazine',
        'gaming', 'game', 'player', 'tournament', 'esports',
        'travel', 'hotel', 'booking', 'reservation', 'flight',

        # File extensions and formats
        'json', 'xml', 'csv', 'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'zip', 'tar', 'gz', 'rar', 'backup', 'dump', 'sql', 'db',
        'log', 'logs', 'error', 'access', 'debug', 'trace',

        # Miscellaneous
        'misc', 'other', 'util', 'utils', 'tools', 'scripts', 'automation',
        'monitor', 'monitoring', 'health', 'status', 'check', 'ping',
        'test', 'testing', 'mock', 'stub', 'sample', 'example',
        'template', 'layout', 'theme', 'style', 'brand', 'logo'
    ]

    def __init__(self, wordlist_dir: Optional[str] = None):
        """
        Initialize wordlist manager

        Args:
            wordlist_dir: Directory containing custom wordlists
        """
        self.wordlist_dir = Path(wordlist_dir) if wordlist_dir else None
        self.loaded_wordlists = {}
        self.custom_wordlists = {}

        # Ensure wordlist directory exists
        if self.wordlist_dir and not self.wordlist_dir.exists():
            self.wordlist_dir.mkdir(parents=True, exist_ok=True)

    def get_builtin_wordlist(self, category: Optional[str] = None) -> List[str]:
        """
        Get built-in wordlist, with fallback to comprehensive wordlist file

        Args:
            category: Optional category filter

        Returns:
            List of words from built-in wordlist or comprehensive wordlist file
        """
        # Try to load s3_bucket_wordlist.txt file first
        s3_wordlist_path = Path(__file__).parent / "s3_bucket_wordlist.txt"
        if s3_wordlist_path.exists():
            try:
                with open(s3_wordlist_path, 'r', encoding='utf-8') as f:
                    words = []
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith('#'):
                            words.append(line.lower())

                logger.info(f"Loaded {len(words)} words from S3 bucket wordlist")
                if category:
                    return self._filter_wordlist_by_category(words, category)
                return words
            except Exception as e:
                logger.warning(f"Failed to load S3 bucket wordlist: {e}, using builtin")

        # Fallback to builtin wordlist
        if category:
            return self._filter_wordlist_by_category(self.BUILTIN_WORDLIST, category)
        return self.BUILTIN_WORDLIST.copy()

    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """
        Load wordlist from file

        Args:
            wordlist_path: Path to wordlist file

        Returns:
            List of words from the wordlist
        """
        wordlist_path = Path(wordlist_path)

        # Check cache first
        if str(wordlist_path) in self.loaded_wordlists:
            return self.loaded_wordlists[str(wordlist_path)]

        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip().lower() for line in f if line.strip()]

            # Filter and validate words
            valid_words = self._validate_wordlist(words)

            # Cache the result
            self.loaded_wordlists[str(wordlist_path)] = valid_words

            logger.info(f"Loaded {len(valid_words)} words from {wordlist_path}")
            return valid_words

        except Exception as e:
            logger.error(f"Error loading wordlist {wordlist_path}: {e}")
            return []

    def create_custom_wordlist(self,
                               name: str,
                               words: List[str],
                               save_to_file: bool = True) -> bool:
        """
        Create a custom wordlist

        Args:
            name: Name of the wordlist
            words: List of words
            save_to_file: Whether to save to file

        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate words
            valid_words = self._validate_wordlist(words)

            # Store in memory
            self.custom_wordlists[name] = valid_words

            # Save to file if requested
            if save_to_file and self.wordlist_dir:
                wordlist_file = self.wordlist_dir / f"{name}.txt"
                with open(wordlist_file, 'w', encoding='utf-8') as f:
                    for word in valid_words:
                        f.write(f"{word}\n")

                logger.info(f"Saved custom wordlist '{name}' with {len(valid_words)} words")

            return True

        except Exception as e:
            logger.error(f"Error creating custom wordlist '{name}': {e}")
            return False

    def get_custom_wordlist(self, name: str) -> Optional[List[str]]:
        """
        Get a custom wordlist

        Args:
            name: Name of the wordlist

        Returns:
            List of words or None if not found
        """
        if name in self.custom_wordlists:
            return self.custom_wordlists[name]

        # Try to load from file
        if self.wordlist_dir:
            wordlist_file = self.wordlist_dir / f"{name}.txt"
            if wordlist_file.exists():
                return self.load_wordlist(str(wordlist_file))

        return None

    def combine_wordlists(self, *wordlist_names: str) -> List[str]:
        """
        Combine multiple wordlists

        Args:
            *wordlist_names: Names of wordlists to combine

        Returns:
            Combined and deduplicated wordlist
        """
        combined_words = set()

        for name in wordlist_names:
            if name == 'builtin':
                combined_words.update(self.BUILTIN_WORDLIST)
            else:
                wordlist = self.get_custom_wordlist(name)
                if wordlist:
                    combined_words.update(wordlist)

        return sorted(list(combined_words))

    def generate_contextual_wordlist(self,
                                     target: str,
                                     context: Dict[str, str]) -> List[str]:
        """
        Generate contextual wordlist based on target and context

        Args:
            target: Target company/domain
            context: Context dictionary with industry, tech stack, etc.

        Returns:
            Contextual wordlist
        """
        contextual_words = set()

        # Add base builtin words
        contextual_words.update(self.BUILTIN_WORDLIST)

        # Add industry-specific words
        industry = context.get('industry', '').lower()
        if industry:
            industry_words = self._get_industry_words(industry)
            contextual_words.update(industry_words)

        # Add technology stack words
        tech_stack = context.get('tech_stack', [])
        if tech_stack:
            for tech in tech_stack:
                tech_words = self._get_tech_words(tech.lower())
                contextual_words.update(tech_words)

        # Add target-derived words
        target_words = self._derive_words_from_target(target)
        contextual_words.update(target_words)

        return sorted(list(contextual_words))

    def _validate_wordlist(self, words: List[str]) -> List[str]:
        """
        Validate and filter wordlist

        Args:
            words: List of words to validate

        Returns:
            List of valid words
        """
        valid_words = []

        for word in words:
            word = word.strip().lower()

            # Skip empty words
            if not word:
                continue

            # Skip words that are too short or too long
            if len(word) < 1 or len(word) > 20:
                continue

            # Skip words with invalid characters
            if not word.replace('-', '').replace('_', '').isalnum():
                continue

            valid_words.append(word)

        # Remove duplicates while preserving order
        seen = set()
        unique_words = []
        for word in valid_words:
            if word not in seen:
                seen.add(word)
                unique_words.append(word)

        return unique_words

    def _filter_wordlist_by_category(self, wordlist: List[str], category: str) -> List[str]:
        """
        Filter wordlist by category

        Args:
            wordlist: List of words to filter
            category: Category to filter by

        Returns:
            Filtered wordlist
        """
        category_keywords = {
            'development': ['dev', 'test', 'stage', 'prod', 'demo', 'qa'],
            'services': ['api', 'web', 'app', 'service', 'cdn', 'static'],
            'data': ['data', 'database', 'backup', 'archive', 'logs', 'analytics'],
            'security': ['security', 'private', 'secure', 'ssl', 'cert', 'key'],
            'infrastructure': ['aws', 'docker', 'kubernetes', 'terraform', 'jenkins'],
            'business': ['admin', 'billing', 'customer', 'order', 'invoice'],
            'content': ['media', 'images', 'documents', 'files', 'uploads']
        }

        keywords = category_keywords.get(category.lower(), [])
        if not keywords:
            return wordlist

        return [word for word in wordlist if any(keyword in word for keyword in keywords)]

    def _get_industry_words(self, industry: str) -> List[str]:
        """Get industry-specific words"""
        industry_words = {
            'finance': ['bank', 'banking', 'payment', 'transaction', 'card', 'loan', 'mortgage'],
            'healthcare': ['patient', 'medical', 'hospital', 'clinic', 'doctor', 'nurse'],
            'retail': ['product', 'inventory', 'order', 'customer', 'checkout', 'cart'],
            'education': ['student', 'course', 'class', 'grade', 'assignment', 'exam'],
            'media': ['content', 'article', 'video', 'audio', 'news', 'blog'],
            'gaming': ['player', 'game', 'level', 'score', 'tournament', 'match'],
            'travel': ['booking', 'reservation', 'hotel', 'flight', 'trip', 'destination']
        }

        return industry_words.get(industry, [])

    def _get_tech_words(self, tech: str) -> List[str]:
        """Get technology-specific words"""
        tech_words = {
            'aws': ['s3', 'ec2', 'lambda', 'rds', 'dynamodb', 'cloudfront'],
            'docker': ['container', 'image', 'registry', 'compose', 'swarm'],
            'kubernetes': ['k8s', 'pod', 'service', 'deployment', 'ingress', 'helm'],
            'react': ['component', 'hook', 'state', 'props', 'jsx', 'redux'],
            'node': ['npm', 'package', 'express', 'server', 'middleware'],
            'python': ['django', 'flask', 'pip', 'virtualenv', 'conda'],
            'java': ['spring', 'maven', 'gradle', 'tomcat', 'jar'],
            'database': ['sql', 'nosql', 'mongodb', 'postgres', 'mysql', 'redis']
        }

        return tech_words.get(tech, [])

    def _derive_words_from_target(self, target: str) -> List[str]:
        """Derive additional words from target"""
        derived_words = []

        # Extract domain parts
        if '.' in target:
            parts = target.split('.')
            derived_words.extend(parts)

        # Extract hyphenated parts
        if '-' in target:
            parts = target.split('-')
            derived_words.extend(parts)

        # Add common variations
        derived_words.extend([
            f"{target}api",
            f"{target}app",
            f"{target}web",
            f"{target}data",
            f"{target}backup"
        ])

        return derived_words

    def get_wordlist_statistics(self) -> Dict[str, int]:
        """Get wordlist statistics"""
        return {
            'builtin_words': len(self.BUILTIN_WORDLIST),
            'loaded_wordlists': len(self.loaded_wordlists),
            'custom_wordlists': len(self.custom_wordlists)
        }

    def save_builtin_wordlist(self, filename: str = 'builtin.txt') -> bool:
        """Save builtin wordlist to file"""
        if not self.wordlist_dir:
            return False

        try:
            wordlist_file = self.wordlist_dir / filename
            with open(wordlist_file, 'w', encoding='utf-8') as f:
                for word in self.BUILTIN_WORDLIST:
                    f.write(f"{word}\n")

            logger.info(f"Saved builtin wordlist to {wordlist_file}")
            return True

        except Exception as e:
            logger.error(f"Error saving builtin wordlist: {e}")
            return False
