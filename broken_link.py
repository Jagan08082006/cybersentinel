"""
broken_link.py
-----------------
Crawls a webpage, finds all the links (<a href="...">) on it,
and checks whether each link works or is broken (404, timeout,
connection error, etc.)
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def get_all_links(url: str) -> list:
    """Fetches a page and returns all the links found on it."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    response = requests.get(url, timeout=8)
    soup = BeautifulSoup(response.text, "html.parser")

    links = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        # Convert relative links (like "/about") into full URLs
        full_url = urljoin(url, href)
        links.append(full_url)

    # Remove duplicates while keeping order
    return list(dict.fromkeys(links))


def check_link(url: str) -> dict:
    """Checks if a single link is working or broken."""
    try:
        response = requests.head(url, timeout=6, allow_redirects=True)
        # Some servers don't support HEAD properly, fall back to GET
        if response.status_code >= 400:
            response = requests.get(url, timeout=6, allow_redirects=True)

        return {
            "url": url,
            "status_code": response.status_code,
            "broken": response.status_code >= 400,
        }
    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "status_code": None,
            "broken": True,
            "error": str(e),
        }


def check_broken_links(page_url: str, max_links: int = 30) -> dict:
    """
    Crawls a page, checks every link found on it, and returns
    a report of which links are working vs broken.

    max_links: safety limit so the scan doesn't take forever on
    pages with hundreds of links.
    """
    report = {
        "page": page_url,
        "total_links_found": 0,
        "checked_links": 0,
        "broken_links": [],
        "working_links_count": 0,
        "error": None,
    }

    try:
        links = get_all_links(page_url)
    except requests.exceptions.RequestException as e:
        report["error"] = f"Could not load page: {e}"
        return report

    report["total_links_found"] = len(links)
    links_to_check = links[:max_links]

    for link in links_to_check:
        result = check_link(link)
        report["checked_links"] += 1
        if result["broken"]:
            report["broken_links"].append(result)
        else:
            report["working_links_count"] += 1

    return report
