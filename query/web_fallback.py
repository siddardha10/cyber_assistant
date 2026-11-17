"""Approval-gated web search using only generic, non-user-specific queries."""

from html.parser import HTMLParser
from urllib.parse import quote

import requests


_SEARCH_TERMS = {
    "general": "Windows system administration help",
    "files": "Windows file and folder management",
    "processes": "Windows process management",
    "services": "Windows service management",
    "applications": "Windows application management",
    "network": "Windows network diagnostics",
}


class _ResultsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results = []
        self._current = None
        self._capture = None
        self._capture_tag = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        classes = attributes.get("class", "").split()
        if tag == "a" and "result__a" in classes:
            self._current = {"title": "", "url": attributes.get("href", "")}
            self._capture = "title"
        elif tag in {"a", "div"} and "result__snippet" in classes and self.results:
            self._capture = "snippet"
            self._capture_tag = tag

    def handle_data(self, data):
        if self._current is not None and self._capture == "title":
            self._current[self._capture] += data
        elif self._capture == "snippet" and self.results:
            self.results[-1]["snippet"] += data

    def handle_endtag(self, tag):
        if self._capture == "snippet" and self._capture_tag == tag:
            self._capture = None
            self._capture_tag = None
            return
        if self._current is None:
            return
        if tag == "a" and self._capture == "title":
            self._current["snippet"] = ""
            self.results.append(self._current)
            self._current = None
            self._capture = None


def search(category: str) -> list[dict]:
    """Search after explicit UI approval; raw user text is never forwarded."""
    query = get_search_query(category)
    response = requests.get(
        "https://html.duckduckgo.com/html/?q=" + quote(query),
        headers={"User-Agent": "CyberSentinel/1.0"},
        timeout=10,
    )
    response.raise_for_status()
    parser = _ResultsParser()
    parser.feed(response.text)
    return parser.results[:5]


def get_search_query(category: str) -> str:
    try:
        return _SEARCH_TERMS[category]
    except KeyError as error:
        raise ValueError("Unsupported web-search category.") from error
