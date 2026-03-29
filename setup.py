"""
setup.py — BlueSentinel V2.0 Package Configuration
====================================================
Standard setuptools packaging for PyPI-compatible installation.

Quick install:
    pip install -e .
    pip install -e ".[pdf]"        # with PDF export
    pip install -e ".[dev]"        # with dev tools

Or use the requirements file directly:
    pip install -r requirements.txt

Author: Valon Canolli
"""

import subprocess
import sys
from pathlib import Path
from setuptools import setup, find_packages

# ── Version ──────────────────────────────────────────────────────────────────
VERSION = '2.1.0'

# ── Read README for long description ─────────────────────────────────────────
readme_path = Path('README.md')
LONG_DESCRIPTION = readme_path.read_text(encoding='utf-8') if readme_path.exists() else ''

# ── Dependencies (must match requirements.txt) ────────────────────────────────
INSTALL_REQUIRES = [
    'yara-python>=4.3.0',
    'requests>=2.31.0',
    'aiohttp>=3.9.0',
    'python-dotenv>=1.0.0',
    'colorama>=0.4.6',
    'tqdm>=4.66.0',
    'psutil>=5.9.0',
    'numpy>=1.26.0',
    'scipy>=1.11.0',
    'scikit-learn>=1.3.0',
    'openai>=1.35.0',
    'anthropic>=0.28.0',
    'flask>=3.0.0',
    'flask-socketio>=5.3.0',
    'python-socketio>=5.10.0',
    'eventlet>=0.35.0',
    'flask-limiter>=3.5.0',
    'jinja2>=3.1.0',
    'pyyaml>=6.0.0',
    'cryptography>=41.0.0',
]

EXTRAS_REQUIRE = {
    'pdf':  ['weasyprint>=62.0'],
    'dev':  ['pytest>=8.2.0', 'pytest-asyncio>=0.23.0', 'pytest-cov>=4.0.0'],
}

# ── Setup configuration ───────────────────────────────────────────────────────
setup(
    name='bluesentinel-v2',
    version=VERSION,
    description=(
        'AI-Augmented Threat Detection Platform for Windows SOC environments. '
        'Features YARA scanning, FFT-based C2 beaconing detection, '
        'MITRE ATT&CK v14 mapping, real-time dashboard, Windows Firewall '
        'integration, IP intelligence, and dual AI triage (GPT-4o / Claude).'
    ),
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Valon Canolli',
    url='https://github.com/valoncanolli/BlueSentinel-V2',
    license='MIT',
    python_requires='>=3.10',
    packages=find_packages(exclude=['tests*', '*.tests', '*.tests.*']),
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    package_data={
        '': [
            'rules/yara/**/*.yar',
            'rules/sigma/*.yml',
            'config/*.json',
            'config/.env.example',
            'dashboard/templates/*.html',
            'dashboard/static/css/*.css',
            'dashboard/static/js/*.js',
            'dashboard/static/js/**/*.js',
            'demo/*.py',
        ],
    },
    entry_points={
        'console_scripts': [
            'bluesentinel=core.orchestrator:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords=(
        'cybersecurity soc blue-team threat-detection yara '
        'mitre-attack beaconing c2-detection windows-security '
        'incident-response threat-intelligence dashboard'
    ),
    project_urls={
        'GitHub':      'https://github.com/valoncanolli/BlueSentinel-V2',
        'Bug Reports': 'https://github.com/valoncanolli/BlueSentinel-V2/issues',
    },
)
