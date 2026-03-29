"""
intelligence/news_client.py — Cybersecurity News Feed Client
=============================================================
Fetches top cybersecurity headlines from multiple sources.

Primary sources (no API key required):
  - The Hacker News RSS: https://feeds.feedburner.com/TheHackersNews
  - BleepingComputer RSS: https://www.bleepingcomputer.com/feed/
  - Krebs on Security RSS: https://krebsonsecurity.com/feed/
  - CISA Alerts RSS: https://www.cisa.gov/news.xml

Secondary (optional, requires NEWS_API_KEY in .env):
  - NewsAPI.org: cybersecurity + infosec query

Returns top 10 most recent headlines with title, source, URL, and timestamp.
Cache: 30-minute TTL (news changes frequently, unlike file hashes).
"""

import json
import time
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.logger import get_logger

logger = get_logger(__name__)

NEWS_CACHE_FILE = Path("cache/news_cache.json")
NEWS_CACHE_TTL  = 1800  # 30 minutes (news changes — TTL is correct here)

RSS_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "color": "#00d4ff",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "color": "#00ff88",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "color": "#ffb800",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/news.xml",
        "color": "#ff3b5c",
    },
]


@dataclass
class NewsItem:
    title: str
    source: str
    url: str
    published: str     # ISO format
    source_color: str  # hex color for the source badge

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "source": self.source,
            "url": self.url,
            "published": self.published,
            "source_color": self.source_color,
        }


class NewsClient:
    """
    Fetches cybersecurity news headlines from RSS feeds.
    Caches results for 30 minutes to avoid hammering news sites.
    """

    def __init__(self):
        self._cache_data: Optional[List[dict]] = None
        self._cache_time: float = 0.0

    def _load_disk_cache(self) -> Optional[List[dict]]:
        """Load cached news from disk if still fresh (< 30 min old)."""
        if not NEWS_CACHE_FILE.exists():
            return None
        try:
            raw = json.loads(NEWS_CACHE_FILE.read_text(encoding="utf-8"))
            age = time.time() - raw.get("fetched_at", 0)
            if age < NEWS_CACHE_TTL:
                return raw.get("items", [])
        except Exception:
            pass
        return None

    def _save_disk_cache(self, items: List[dict]):
        """Save fetched news to disk cache."""
        try:
            NEWS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            NEWS_CACHE_FILE.write_text(
                json.dumps({
                    "fetched_at": time.time(),
                    "items": items,
                }, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            logger.debug(f"Could not save news cache: {e}")

    def _fetch_rss(self, feed: dict) -> List[NewsItem]:
        """Fetch and parse a single RSS feed. Returns up to 5 items."""
        if not HAS_REQUESTS:
            return []
        try:
            resp = _requests.get(
                feed["url"],
                timeout=8,
                headers={"User-Agent": "BlueSentinel/2.0 RSS Reader"},
            )
            resp.raise_for_status()
            root = ET.fromstring(resp.content)

            items = []
            # Handle both RSS 2.0 and Atom formats
            channel = root.find("channel")
            entries = (channel or root).findall("item") or root.findall(
                "{http://www.w3.org/2005/Atom}entry"
            )

            for entry in entries[:5]:
                # Title
                title_el = entry.find("title") or entry.find(
                    "{http://www.w3.org/2005/Atom}title"
                )
                title = (title_el.text or "").strip() if title_el is not None else ""
                if not title:
                    continue

                # URL
                link_el = entry.find("link") or entry.find(
                    "{http://www.w3.org/2005/Atom}link"
                )
                if link_el is not None:
                    url = link_el.text or link_el.get("href", "") or ""
                else:
                    url = ""

                # Date
                pub_el = (
                    entry.find("pubDate")
                    or entry.find("published")
                    or entry.find("{http://www.w3.org/2005/Atom}published")
                )
                published = (pub_el.text or "").strip() if pub_el is not None else ""

                if title and url:
                    items.append(NewsItem(
                        title=title[:120],
                        source=feed["name"],
                        url=url.strip(),
                        published=published,
                        source_color=feed["color"],
                    ))

            return items

        except Exception as e:
            logger.debug(f"RSS fetch failed for {feed['name']}: {e}")
            return []

    def _fetch_newsapi(self) -> List[NewsItem]:
        """Fetch from NewsAPI.org if API key is configured."""
        api_key = os.getenv("NEWS_API_KEY", "").strip()
        if not api_key or not HAS_REQUESTS:
            return []

        try:
            resp = _requests.get(
                "https://newsapi.org/v2/everything",
                params={
                    "q": "cybersecurity OR ransomware OR malware OR \"data breach\"",
                    "language": "en",
                    "sortBy": "publishedAt",
                    "pageSize": 10,
                    "apiKey": api_key,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                items = []
                for article in data.get("articles", [])[:10]:
                    title = (article.get("title") or "").strip()
                    url   = (article.get("url") or "").strip()
                    if title and url and title != "[Removed]":
                        items.append(NewsItem(
                            title=title[:120],
                            source=article.get("source", {}).get("name", "NewsAPI"),
                            url=url,
                            published=article.get("publishedAt", ""),
                            source_color="#b44fff",
                        ))
                return items
        except Exception as e:
            logger.debug(f"NewsAPI fetch failed: {e}")
        return []

    def _fetch_all_parallel(self) -> List[NewsItem]:
        """Fetch all RSS feeds concurrently. Returns combined results."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        items: List[NewsItem] = []
        with ThreadPoolExecutor(max_workers=len(RSS_FEEDS)) as pool:
            futures = {pool.submit(self._fetch_rss, feed): feed for feed in RSS_FEEDS}
            for fut in as_completed(futures, timeout=8):
                try:
                    items.extend(fut.result())
                except Exception:
                    pass
        return items

    def get_headlines(self, limit: int = 10) -> List[dict]:
        """
        Return top N cybersecurity headlines.
        Uses 30-minute TTL cache. Falls back to cached data on error.
        """
        # Check in-memory cache first
        if self._cache_data and (time.time() - self._cache_time) < NEWS_CACHE_TTL:
            return self._cache_data[:limit]

        # Check disk cache
        disk = self._load_disk_cache()
        if disk:
            self._cache_data = disk
            self._cache_time = time.time()
            return disk[:limit]

        # Fetch fresh data — NewsAPI first, then parallel RSS
        items = self._fetch_newsapi() or self._fetch_all_parallel()
        result = [i.to_dict() if hasattr(i, 'to_dict') else i for i in items[:limit]]

        if result:
            self._cache_data = result
            self._cache_time = time.time()
            self._save_disk_cache(result)
            logger.info(f"News fetched: {len(result)} headlines cached for 30 min")
        elif self._cache_data:
            return self._cache_data[:limit]  # stale fallback
        else:
            # Static fallback so dashboard always shows something
            logger.warning("News fetch failed — using static fallback")
            result = [
                {"title": "The Hacker News — Cybersecurity headlines", "source": "The Hacker News",
                 "url": "https://thehackernews.com/", "published": "", "source_color": "#00d4ff"},
                {"title": "BleepingComputer — Latest security news", "source": "BleepingComputer",
                 "url": "https://www.bleepingcomputer.com/", "published": "", "source_color": "#00ff88"},
                {"title": "Krebs on Security — In-depth security news", "source": "Krebs on Security",
                 "url": "https://krebsonsecurity.com/", "published": "", "source_color": "#ffb800"},
                {"title": "CISA — Cybersecurity alerts and advisories", "source": "CISA",
                 "url": "https://www.cisa.gov/", "published": "", "source_color": "#ff3b5c"},
            ]

        return result[:limit]


# Module-level singleton
_news_client: Optional[NewsClient] = None


def get_news_client() -> NewsClient:
    global _news_client
    if _news_client is None:
        _news_client = NewsClient()
    return _news_client
