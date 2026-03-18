
from __future__ import annotations
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, List
import requests

PYPI_ENDPOINT = "https://pypi.org/pypi/{name}/json"
UA = {"User-Agent": "reqsum/0.1 (+https://example.invalid)"}

@dataclass
class PackageMetadata:
    summary: str
    category: str
    keywords: str
    classifiers: List[str]

class Cache:
    def __init__(self, path: Path):
        self.path = path
        self._data = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def get(self, name: str) -> Optional[PackageMetadata]:
        data = self._data.get(name)
        if data and isinstance(data, dict):
            return PackageMetadata(**data)
        return None

    def set(self, name: str, metadata: PackageMetadata):
        self._data[name] = {
            "summary": metadata.summary,
            "category": metadata.category,
            "keywords": metadata.keywords,
            "classifiers": metadata.classifiers
        }

    def get_summary(self, name: str) -> Optional[str]:
        data = self._data.get(name)
        if data:
            if isinstance(data, str):
                return data
            elif isinstance(data, dict):
                return data.get("summary")
        return None

    def set_summary(self, name: str, summary: str):
        if name in self._data and isinstance(self._data[name], dict):
            self._data[name]["summary"] = summary
        else:
            self._data[name] = summary

    def save(self):
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")

def clean_classifier_path(classifier_path: list[str]) -> str:
    """Remove version numbers and excessive granularity from classifier paths"""
    if len(classifier_path) <= 1:
        return " / ".join(classifier_path)
    
    # For Framework categories, keep only the main framework name
    if classifier_path[0] == "Framework" and len(classifier_path) > 1:
        framework_name = classifier_path[1]
        # Skip any version numbers in subsequent parts
        if any(part.isdigit() for part in classifier_path[2:]):
            return f"Framework / {framework_name}"
        return " / ".join(classifier_path[:2])
    
    # For Programming Language, keep major version only
    if classifier_path[0] == "Programming Language":
        if len(classifier_path) > 2 and classifier_path[2].isdigit():
            return " / ".join(classifier_path[:2])
        return " / ".join(classifier_path[:2])
    
    # For other categories, limit to 2-3 levels and remove versions
    cleaned = []
    for part in classifier_path[:3]:
        if part.isdigit():
            continue
        cleaned.append(part)
    
    return " / ".join(cleaned)

def matches_pattern(name: str, patterns: list[str]) -> bool:
    """Check if package name matches any of the given patterns (contains throughout)"""
    name_lower = name.lower()
    for pattern in patterns:
        if pattern in name_lower:
            return True
    return False

def check_suspicious_package(name: str) -> tuple[bool, str]:
    """Basic security check for potentially suspicious packages"""
    name_lower = name.lower()
    
    # Common suspicious patterns
    suspicious_patterns = [
        'request',  # Common typo of 'requests'
        'urllib',    # Should use 'urllib3'
        'setuptools',  # Usually shouldn't be direct dependency
        'pip',       # Usually shouldn't be direct dependency
        'python',    # Often suspicious if not standard library
    ]
    
    # Check for common typosquatting patterns
    known_legit = {
        'requests', 'urllib3', 'setuptools', 'pip', 'python-dateutil'
    }
    
    if name_lower not in known_legit:
        for pattern in suspicious_patterns:
            if pattern in name_lower and name != pattern:
                return True, f"Possible typo of '{pattern}'"
    
    return False, ""

def derive_category(classifiers: list[str], package_name: str = "", summary: str = "", keywords: str = "") -> str:
    """
    Comprehensive package categorization based on extensive PyPI data analysis
    and knowledge of Python package naming patterns.
    """
    
    # Convert to lowercase for easier matching
    package_name_lower = package_name.lower()
    keywords_lower = keywords.lower()
    summary_lower = summary.lower()
    classifiers_text = " ".join(classifiers).lower()
    
    
    
    # Security check first
    is_suspicious, reason = check_suspicious_package(package_name)
    if is_suspicious:
        return f"WARNING: Suspicious Package - {reason}"
    
    # CLOUD SERVICES (highest priority)
    
    # Google Cloud Services
    google_patterns = [
        'google', 'googleapis', 'grpc', 'proto', 'gcp', 'bigquery', 'vertex', 
        'gcs', 'google-cloud', 'firebase', 'gke', 'run', 'cloudfunctions',
        'appengine', 'cloudsql', 'pubsub', 'dataflow', 'dataproc'
    ]
    if matches_pattern(package_name_lower, google_patterns):
        return 'Cloud Services / Google Cloud'
    
    # Amazon Web Services
    aws_patterns = [
        'boto', 'aws', 's3', 'ec2', 'lambda', 'athena', 'redshift', 'rds',
        'cloudwatch', 'dynamodb', 'sns', 'sqs', 'ecs', 'eks', 'cloudformation'
    ]
    if matches_pattern(package_name_lower, aws_patterns):
        return 'Cloud Services / AWS'
    
    # Microsoft Azure
    azure_patterns = [
        'azure', 'msal', 'msrest', 'azure-storage', 'azure-keyvault', 
        'azure-cosmos', 'azure-identity', 'azure-mgmt'
    ]
    if matches_pattern(package_name_lower, azure_patterns):
        return 'Cloud Services / Microsoft Azure'
    
    # WEB FRAMEWORKS
    
    # Django ecosystem
    django_patterns = [
        'django', 'djangorestframework', 'drf', 'django-cms', 'wagtail',
        'django-allauth', 'django-debug-toolbar', 'django-extensions'
    ]
    if matches_pattern(package_name_lower, django_patterns):
        if package_name_lower.startswith('django'):
            return 'Web Frameworks / Django'
        return 'Web Frameworks / Django Extensions'
    
    # Flask ecosystem
    flask_patterns = [
        'flask', 'flask-', 'jinja', 'werkzeug', 'click', 'markupsafe',
        'itsdangerous', 'blinker'
    ]
    if matches_pattern(package_name_lower, flask_patterns):
        if package_name_lower.startswith('flask'):
            return 'Web Frameworks / Flask'
        return 'Web Frameworks / Flask Extensions'
    
    # FastAPI ecosystem
    fastapi_patterns = [
        'fastapi', 'starlette', 'pydantic', 'uvicorn', 'httpx', 'httptools',
        'python-multipart', 'h11', 'ujson', 'orjson'
    ]
    if matches_pattern(package_name_lower, fastapi_patterns):
        if package_name_lower.startswith('fastapi'):
            return 'Web Frameworks / FastAPI'
        return 'Web Frameworks / ASGI & FastAPI'
    
    # Other Web Frameworks
    web_framework_patterns = [
        'tornado', 'pyramid', 'bottle', 'sanic', 'aiohttp', 'quart',
        'falcon', 'hug', 'responder', 'vibora'
    ]
    if matches_pattern(package_name_lower, web_framework_patterns):
        return 'Web Frameworks / Other'
    
    # WSGI/ASGI servers
    server_patterns = [
        'gunicorn', 'uwsgi', 'waitress', 'gevent', 'eventlet', 'meinheld',
        'daphne', 'hypercorn'
    ]
    if matches_pattern(package_name_lower, server_patterns):
        return 'Web Servers & Deployment'
    
    # DATA SCIENCE & MACHINE LEARNING
    
    # Core ML/AI frameworks
    ml_core_patterns = [
        'tensorflow', 'torch', 'pytorch', 'jax', 'mxnet', 'caffe', 'theano',
        'chainer', 'paddle', 'sklearn', 'scikit-learn', 'xgboost', 'lightgbm',
        'catboost', 'huggingface', 'transformers', 'datasets', 'tokenizers'
    ]
    if matches_pattern(package_name_lower, ml_core_patterns):
        return 'Machine Learning / Core Frameworks'
    
    # Data Science & Analysis
    data_science_patterns = [
        'pandas', 'numpy', 'scipy', 'polars', 'dask', 'vaex', 'modin',
        'datatable', 'cudf', 'rapids'
    ]
    if matches_pattern(package_name_lower, data_science_patterns):
        return 'Data Science & Analysis'
    
    # Visualization
    viz_patterns = [
        'matplotlib', 'plotly', 'seaborn', 'bokeh', 'altair', 'holoviews',
        'plotnine', 'ggplot', 'pygal', 'networkx', 'graph-tool'
    ]
    if matches_pattern(package_name_lower, viz_patterns):
        return 'Data Visualization'
    
    # DATABASE & STORAGE
    
    # Database clients
    db_patterns = [
        'psycopg', 'pg8000', 'asyncpg', 'mysql', 'pymysql', 'mysql-connector',
        'pymongo', 'motor', 'elasticsearch', 'opensearch', 'redis', 'aioredis',
        'hiredis', 'sqlite', 'apsw', 'duckdb', 'clickhouse'
    ]
    if matches_pattern(package_name_lower, db_patterns):
        return 'Database & Storage / Clients'
    
    # ORM & Query Builders
    orm_patterns = [
        'sqlalchemy', 'alembic', 'peewee', 'pony', 'tinydb', 'dataset',
        'records', 'databases'
    ]
    if matches_pattern(package_name_lower, orm_patterns):
        return 'Database & Storage / ORM'
    
    # TESTING & CODE QUALITY
    
    # Testing frameworks
    testing_patterns = [
        'pytest', 'unittest', 'nose', 'tox', 'hypothesis', 'faker',
        'factory_boy', 'mock', 'responses', 'vcr', 'testfixtures'
    ]
    if matches_pattern(package_name_lower, testing_patterns):
        return 'Testing & Code Quality / Testing'
    
    # Code quality & linting
    quality_patterns = [
        'black', 'isort', 'flake8', 'pylint', 'mypy', 'bandit', 'ruff',
        'pycodestyle', 'pyflakes', 'mccabe', 'autopep8', 'yapf', 'pre-commit'
    ]
    if matches_pattern(package_name_lower, quality_patterns):
        return 'Testing & Code Quality / Code Quality'
    
    # Coverage & Profiling
    coverage_patterns = [
        'coverage', 'coveralls', 'codecov', 'pytest-cov', 'memory-profiler',
        'line-profiler', 'py-spy', 'scalene'
    ]
    if matches_pattern(package_name_lower, coverage_patterns):
        return 'Testing & Code Quality / Coverage & Profiling'
    
    # HTTP & API CLIENTS
    http_patterns = [
        'requests', 'httpx', 'aiohttp', 'urllib3', 'httpcore', 'httpie',
        'treq', 'hyper', 'furl', 'urllib'
    ]
    if matches_pattern(package_name_lower, http_patterns):
        return 'HTTP & API Clients'
    
    # ASYNC & CONCURRENCY
    async_patterns = [
        'asyncio', 'async', 'aio', 'celery', 'rq', 'dramatiq', 'kombu',
        'billiard', 'vine', 'gevent', 'eventlet', 'greenlet', 'uvloop',
        'asgiref'
    ]
    if matches_pattern(package_name_lower, async_patterns):
        return 'Async & Task Queues'
    
    # DOCUMENTATION
    doc_patterns = [
        'sphinx', 'mkdocs', 'docutils', 'alabaster', 'sphinxcontrib',
        'readthedocs', 'pdoc', 'pydoc', 'autodoc'
    ]
    if matches_pattern(package_name_lower, doc_patterns):
        return 'Documentation & API Specs'
    
    # FILE & DOCUMENT PROCESSING
    file_patterns = [
        'pdf', 'pypdf', 'pdfminer', 'pdftotext', 'openpyxl', 'xlrd', 'xlwt',
        'xlsxwriter', 'pillow', 'pillow-', 'pymupdf', 'reportlab', 'docx',
        'python-docx', 'pptx', 'xls', 'csv', 'parquet', 'arrow', 'feather'
    ]
    if matches_pattern(package_name_lower, file_patterns):
        return 'File & Document Processing'
    
    # TEXT PROCESSING
    text_patterns = [
        'beautifulsoup', 'bs4', 'lxml', 'html5lib', 'htmlparser', 'nltk',
        'spacy', 'textblob', 'gensim', 'jieba', 'regex', 're', 'markup',
        'yaml', 'toml', 'json', 'xml', 'html', 'css', 'pygments'
    ]
    if matches_pattern(package_name_lower, text_patterns):
        return 'Text Processing & Markup'
    
    # DATE & TIME
    date_patterns = [
        'dateutil', 'pytz', 'tzdata', 'pendulum', 'arrow', 'moment',
        'delorean', 'mayfly', 'chronyk', 'icalendar', 'iso8601', 'isodate'
    ]
    if matches_pattern(package_name_lower, date_patterns):
        return 'Date & Time Handling'
    
    # SECURITY & CRYPTOGRAPHY
    crypto_patterns = [
        'cryptography', 'pyopenssl', 'pycrypto', 'bcrypt', 'passlib',
        'argon2', 'hashlib', 'jwt', 'pyjwt', 'authlib', 'oauthlib',
        'secretstorage', 'keyring'
    ]
    if matches_pattern(package_name_lower, crypto_patterns):
        return 'Security & Cryptography'
    
    # CONFIGURATION & ENVIRONMENT
    config_patterns = [
        'dotenv', 'python-dotenv', 'environ', 'configparser', 'hydra',
        'pydantic-settings', 'dynaconf', 'decouple', 'config'
    ]
    if matches_pattern(package_name_lower, config_patterns):
        return 'Configuration & Environment'
    
    # LOGGING & MONITORING
    logging_patterns = [
        'loguru', 'structlog', 'colorlog', 'logging', 'sentry', 'rollbar',
        'prometheus', 'grafana', 'datadog', 'newrelic', 'elastic-apm'
    ]
    if matches_pattern(package_name_lower, logging_patterns):
        return 'Logging & Monitoring'
    
    # DEVELOPMENT TOOLS
    dev_tools_patterns = [
        'ipython', 'jupyter', 'notebook', 'jupyterlab', 'ptpython', 'bpython',
        'pdb', 'ipdb', 'pdb++', 'pudb', 'debugpy', 'breakpoint'
    ]
    if matches_pattern(package_name_lower, dev_tools_patterns):
        return 'Development Tools & IDEs'
    
    # CORE PYTHON LIBRARIES
    core_patterns = [
        'typing', 'dataclasses', 'attrs', 'wrapt', 'decorator', 'inflection',
        'humanize', 'slugify', 'six', 'distlib', 'packaging', 'setuptools',
        'wheel', 'pip', 'importlib', 'inspect', 'ast', 'certifi', 'charset',
        'idna', 'urllib3', 'requests', 'click', 'platformdirs'
    ]
    if matches_pattern(package_name_lower, core_patterns):
        return 'Core Python Libraries'
    
    # COMMAND LINE & CLI
    cli_patterns = [
        'click', 'typer', 'argparse', 'docopt', 'argh', 'cliff', 'cement',
        'plumbum', 'invoke', 'fabric', 'paramiko', 'rich', 'textual',
        'colorama', 'termcolor', 'wcwidth', 'prompt'
    ]
    if matches_pattern(package_name_lower, cli_patterns):
        return 'Command Line & CLI Tools'
    
    # VALIDATION & SERIALIZATION
    validation_patterns = [
        'pydantic', 'marshmallow', 'cerberus', 'jsonschema', 'voluptuous',
        'schematics', 'colander', 'serpy', 'serde'
    ]
    if matches_pattern(package_name_lower, validation_patterns):
        return 'Validation & Serialization'
    
    # IMAGE PROCESSING
    image_patterns = [
        'pillow', 'pil', 'opencv', 'cv2', 'imageio', 'scikit-image',
        'wand', 'magick', 'photoshop', 'exif', 'tiff', 'matplotlib'
    ]
    if matches_pattern(package_name_lower, image_patterns):
        return 'Image Processing & Computer Vision'
    
    # NETWORKING & COMMUNICATION
    network_patterns = [
        'socket', 'websocket', 'aiofiles', 'watchfiles', 'paramiko',
        'fabric', 'ssh', 'telnet', 'ftp', 'sftp', 'protocol', 'message',
        'amqp', 'rabbitmq', 'kafka', 'redis', 'mqtt', 'zeromq', 'websockets',
        'autobahn', 'channel', 'flower'
    ]
    if matches_pattern(package_name_lower, network_patterns):
        return 'Networking & Communication'
    
    # PERFORMANCE & OPTIMIZATION
    perf_patterns = [
        'numba', 'cython', 'pyjit', 'pypy', 'cffi', 'swig', 'compile',
        'optimize', 'speed', 'fast', 'uvloop'
    ]
    if matches_pattern(package_name_lower, perf_patterns):
        return 'Performance & Optimization'
    
    # SCIENTIFIC COMPUTING
    scientific_patterns = [
        'scipy', 'numpy', 'sympy', 'mpmath', 'sage', 'julia', 'rpy2',
        'biopython', 'astropy', 'sunpy', 'earthpy'
    ]
    if matches_pattern(package_name_lower, scientific_patterns):
        return 'Scientific Computing'
    
    # WEB SCRAPING
    scraping_patterns = [
        'scrapy', 'beautifulsoup', 'selenium', 'playwright', 'requests-html',
        'lxml', 'mechanize', 'urllib', 'spiders', 'crawler'
    ]
    if matches_pattern(package_name_lower, scraping_patterns):
        return 'Web Scraping & Automation'
    
    # TYPE STUBS
    stub_patterns = [
        'types-', 'typing-', 'stubs', 'mypy-stubs', 'python-types'
    ]
    if matches_pattern(package_name_lower, stub_patterns):
        return 'Type Annotations & Stubs'
    
    # FALLBACK: Use summary and keywords
    fallback_terms = {
        'web framework': 'Web Frameworks / Other',
        'api': 'API Development',
        'http': 'HTTP & Network',
        'database': 'Database & Storage',
        'testing': 'Testing & Code Quality',
        'documentation': 'Documentation & API Specs',
        'security': 'Security & Cryptography',
        'machine learning': 'Machine Learning / Core Frameworks',
        'data science': 'Data Science & Analysis',
        'image': 'Image Processing & Computer Vision',
        'cli': 'Command Line & CLI Tools',
        'async': 'Async & Task Queues',
        'config': 'Configuration & Environment'
    }
    
    all_text = f"{summary_lower} {keywords_lower} {classifiers_text}"
    for term, category in fallback_terms.items():
        if term in all_text:
            return category
    
    # Very last fallback: use cleaned classifiers
    if classifiers:
        priority = {"Framework": 0, "Topic": 1, "Programming Language": 2, "Intended Audience": 3}
        parsed_classifiers = []
        for classifier in classifiers:
            parts = classifier.split(" :: ")
            if len(parts) >= 2:
                cleaned = " / ".join(parts[:2])
                parsed_classifiers.append((priority.get(parts[0], 99), parts[0], cleaned))
        
        if parsed_classifiers:
            parsed_classifiers.sort(key=lambda x: (x[0], x[2]))
            return parsed_classifiers[0][2]
    
    return 'Other / Uncategorized'




def fetch_metadata(name: str, cache: Cache, timeout: float = 10.0) -> Optional[PackageMetadata]:
    name = name.strip()
    if not name:
        return None
    cached = cache.get(name)
    if cached:
        return cached
    url = PYPI_ENDPOINT.format(name=name)
    try:
        resp = requests.get(url, headers=UA, timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
        info = data.get("info", {})
        summary = (info.get("summary") or "").strip()
        classifiers = info.get("classifiers", [])
        keywords = (info.get("keywords") or "").strip()
        category = derive_category(classifiers, name, summary, keywords)
        
        metadata = PackageMetadata(
            summary=summary,
            category=category,
            keywords=keywords,
            classifiers=classifiers
        )
        cache.set(name, metadata)
        return metadata
    except Exception:
        return None

def fetch_summary(name: str, cache: Cache, timeout: float = 10.0) -> Optional[str]:
    metadata = fetch_metadata(name, cache, timeout)
    return metadata.summary if metadata else None
