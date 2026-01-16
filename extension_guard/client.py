"""Socket Extension Guard API Client."""

import os
import re
import logging
from typing import Optional
from urllib.parse import urlparse

import requests

from .models import Alert, ExtensionScanResult, Severity

logger = logging.getLogger(__name__)


class ExtensionGuardError(Exception):
    """Base exception for Extension Guard errors."""
    pass


class AuthenticationError(ExtensionGuardError):
    """API authentication failed."""
    pass


class RateLimitError(ExtensionGuardError):
    """API rate limit exceeded."""
    pass


class ExtensionGuardClient:
    """
    Client for Socket's Extension Guard API.

    Scans Chrome extensions for security risks including malware,
    dangerous permissions, and risky code patterns.

    Usage:
        client = ExtensionGuardClient()  # Uses SOCKET_API_KEY env var
        result = client.scan("cjpalhdlnbpafiamejdnhcphjbkeiagm")
        print(result.recommendation)
    """

    BASE_URL = "https://api.socket.dev/v0"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the client.

        Args:
            api_key: Socket API key. If not provided, reads from
                     SOCKET_API_KEY environment variable.

        Raises:
            ValueError: If no API key is provided or found.
        """
        self.api_key = api_key or os.getenv("SOCKET_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Socket API key required. Set SOCKET_API_KEY environment variable "
                "or pass api_key parameter. Get your key at: "
                "https://socket.dev/dashboard/settings/api-tokens"
            )

    def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> requests.Response:
        """Make authenticated API request."""
        url = f"{self.BASE_URL}{path}"
        headers = kwargs.pop("headers", {})
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

        response = requests.request(
            method,
            url,
            headers=headers,
            auth=(self.api_key, ""),
            timeout=kwargs.pop("timeout", 30),
            **kwargs,
        )

        if response.status_code == 401:
            raise AuthenticationError(
                "Invalid API key. Get your key at: "
                "https://socket.dev/dashboard/settings/api-tokens"
            )
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "60")
            raise RateLimitError(
                f"Rate limit exceeded. Retry after {retry_after} seconds."
            )

        return response

    @staticmethod
    def extract_extension_id(input_str: str) -> str:
        """
        Extract Chrome extension ID from various input formats.

        Supports:
            - Raw extension ID: "cjpalhdlnbpafiamejdnhcphjbkeiagm"
            - Chrome Web Store URL: "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
            - Short URL: "https://chrome.google.com/webstore/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm"

        Args:
            input_str: Extension ID or Chrome Web Store URL

        Returns:
            32-character extension ID

        Raises:
            ValueError: If no valid extension ID found
        """
        input_str = input_str.strip()

        # Chrome extension IDs are 32 lowercase letters
        id_pattern = r"[a-z]{32}"

        # Check if input is already a valid ID
        if re.fullmatch(id_pattern, input_str):
            return input_str

        # Try to extract from URL
        if "chrome" in input_str.lower() or "webstore" in input_str.lower():
            match = re.search(id_pattern, input_str)
            if match:
                return match.group()

        # Try parsing as URL and checking path segments
        try:
            parsed = urlparse(input_str)
            path_parts = parsed.path.strip("/").split("/")
            for part in path_parts:
                if re.fullmatch(id_pattern, part):
                    return part
        except Exception:
            pass

        raise ValueError(
            f"Could not extract extension ID from: {input_str!r}. "
            f"Expected 32 lowercase letters or Chrome Web Store URL."
        )

    def scan(self, extension_id: str) -> ExtensionScanResult:
        """
        Scan a single Chrome extension.

        Args:
            extension_id: Extension ID or Chrome Web Store URL

        Returns:
            ExtensionScanResult with alerts and recommendation
        """
        ext_id = self.extract_extension_id(extension_id)
        purl = f"pkg:chrome/{ext_id}"

        logger.info(f"Scanning extension: {ext_id}")

        try:
            response = self._request(
                "POST",
                "/purl?alerts=true",
                json={"components": [{"purl": purl}]},
            )
            response.raise_for_status()
            data = response.json()

            return self._parse_result(data, purl)

        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            return ExtensionScanResult(
                id="",
                name=ext_id,
                version="",
                size=0,
                score_overall=0,
                score_supply_chain=0,
                score_vulnerability=0,
                input_purl=purl,
                error=str(e),
            )

    def scan_batch(
        self,
        extension_ids: list[str],
        batch_size: int = 50,
    ) -> list[ExtensionScanResult]:
        """
        Scan multiple extensions efficiently.

        Args:
            extension_ids: List of extension IDs or URLs
            batch_size: Number of extensions per API call (max 100)

        Returns:
            List of ExtensionScanResult objects
        """
        # Extract and deduplicate IDs
        ids = []
        for ext in extension_ids:
            try:
                ext_id = self.extract_extension_id(ext)
                if ext_id not in ids:
                    ids.append(ext_id)
            except ValueError as e:
                logger.warning(f"Skipping invalid input: {e}")

        if not ids:
            return []

        results = []
        for i in range(0, len(ids), batch_size):
            batch = ids[i : i + batch_size]
            logger.info(f"Scanning batch {i // batch_size + 1}: {len(batch)} extensions")

            purls = [f"pkg:chrome/{ext_id}" for ext_id in batch]

            try:
                response = self._request(
                    "POST",
                    "/purl?alerts=true",
                    json={"components": [{"purl": p} for p in purls]},
                    timeout=60,
                )
                response.raise_for_status()

                # Response may be single object or array
                data = response.json()
                if isinstance(data, list):
                    for item in data:
                        purl = item.get("inputPurl", "")
                        results.append(self._parse_result(item, purl))
                else:
                    purl = data.get("inputPurl", purls[0] if purls else "")
                    results.append(self._parse_result(data, purl))

            except requests.RequestException as e:
                logger.error(f"Batch request failed: {e}")
                # Create error results for this batch
                for ext_id, purl in zip(batch, purls):
                    results.append(ExtensionScanResult(
                        id="",
                        name=ext_id,
                        version="",
                        size=0,
                        score_overall=0,
                        score_supply_chain=0,
                        score_vulnerability=0,
                        input_purl=purl,
                        error=str(e),
                    ))

        return results

    def _parse_result(self, data: dict, input_purl: str) -> ExtensionScanResult:
        """Parse API response into ExtensionScanResult."""
        score = data.get("score", {})

        # Handle error responses
        if "error" in data:
            return ExtensionScanResult(
                id="",
                name=input_purl.replace("pkg:chrome/", ""),
                version="",
                size=0,
                score_overall=0,
                score_supply_chain=0,
                score_vulnerability=0,
                input_purl=input_purl,
                error=data["error"].get("message", str(data["error"])),
            )

        return ExtensionScanResult(
            id=data.get("id", ""),
            name=data.get("name", ""),
            version=data.get("version", ""),
            size=data.get("size", 0),
            score_overall=float(score.get("overall", 0)),
            score_supply_chain=float(score.get("supplyChain", 0)),
            score_vulnerability=float(score.get("vulnerability", 0)),
            alerts=[Alert.from_dict(a) for a in data.get("alerts", [])],
            input_purl=input_purl,
            raw=data,
        )

    def get_supported_ecosystems(self) -> dict:
        """Get list of supported ecosystems (for debugging)."""
        response = self._request("GET", "/report/supported")
        response.raise_for_status()
        return response.json()
