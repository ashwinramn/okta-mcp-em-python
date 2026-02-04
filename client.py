"""
Okta API Client with rate limiting and retry logic.
"""
import os
import sys
import time
import asyncio
import re
import json
import logging
import random
import datetime
from typing import Dict, Optional, Any
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

# Load .env from project root (same directory as this file)
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

# Logger setup
logger = logging.getLogger("okta_mcp")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

# -- CONFIGURATION --
RATE_LIMIT_CONFIG = {
    "safetyThreshold": 0.70,
    "concurrentLimit": 75,
    "defaultLimit": 600,
    "minDelayMs": 50,
    "resetBufferMs": 1000,
}

ENDPOINT_LIMITS = {
    '/api/v1/apps': 100,
    '/api/v1/apps/{id}': 500,
    '/api/v1/groups': 500,
    '/api/v1/groups/{id}': 1000,
    '/api/v1/users': 600,
    '/api/v1/users/{id}': 600,
    '/api/v1/users/{idOrLogin}': 2000,
    '/governance/api/v1': 1200,
    '/api/v1': 1200,
}

RETRY_CONFIG = {
    "maxRetries": 3,
    "baseDelayMs": 1000,
    "maxDelayMs": 60000,
    "backoffMultiplier": 2,
}

class RateLimitTracker:
    def __init__(self):
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.active_requests = 0
        self.request_history = []
        self.stats = {
            "totalRequests": 0,
            "throttledRequests": 0,
            "rateLimitHits": 0,
            "lastReset": time.time() * 1000
        }

    def get_endpoint_category(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path

            if '/governance/api/v1/' in path:
                return '/governance/api/v1'
            
            if re.search(r'/api/v1/users/[a-zA-Z0-9]+$', path):
                return '/api/v1/users/{idOrLogin}'
            if re.search(r'/api/v1/users/[a-zA-Z0-9]+/', path):
                return '/api/v1/users/{id}'
            
            if re.search(r'/api/v1/apps/[a-zA-Z0-9]+$', path):
                return '/api/v1/apps/{id}'
            if re.search(r'/api/v1/apps/[a-zA-Z0-9]+/', path):
                return '/api/v1/apps/{id}'

            if re.search(r'/api/v1/groups/[a-zA-Z0-9]+$', path):
                return '/api/v1/groups/{id}'
            if re.search(r'/api/v1/groups/[a-zA-Z0-9]+/', path):
                return '/api/v1/groups/{id}'

            if path.rstrip('/') == '/api/v1/users': return '/api/v1/users'
            if path.rstrip('/') == '/api/v1/apps': return '/api/v1/apps'
            if path.rstrip('/') == '/api/v1/groups': return '/api/v1/groups'

            if path.startswith('/api/v1'):
                return '/api/v1'
            
            return 'unknown'
        except Exception:
            return 'unknown'

    def update_from_headers(self, url: str, headers: httpx.Headers):
        category = self.get_endpoint_category(url)
        
        limit = headers.get("x-rate-limit-limit")
        remaining = headers.get("x-rate-limit-remaining")
        reset = headers.get("x-rate-limit-reset")

        if limit and remaining and reset:
            try:
                limit_val = int(limit)
                remaining_val = int(remaining)
                reset_val = int(reset)
                
                self.endpoints[category] = {
                    "limit": limit_val,
                    "remaining": remaining_val,
                    "resetTime": reset_val * 1000,
                    "lastUpdated": time.time() * 1000
                }
                
                percent_used = ((limit_val - remaining_val) / limit_val) * 100
                if percent_used > 50:
                    logger.warning(f"[RATE LIMIT] {category}: {remaining_val}/{limit_val} remaining")
            except ValueError:
                pass

    def can_make_request(self, url: str) -> Dict[str, Any]:
        category = self.get_endpoint_category(url)
        endpoint_info = self.endpoints.get(category)
        now = time.time() * 1000

        if self.active_requests >= RATE_LIMIT_CONFIG["concurrentLimit"]:
             return {
                "canProceed": False,
                "waitMs": 100,
                "reason": f"Concurrent limit reached ({self.active_requests})"
            }

        if endpoint_info:
            limit = endpoint_info["limit"]
            remaining = endpoint_info["remaining"]
            reset_time = endpoint_info["resetTime"]

            if now > reset_time + RATE_LIMIT_CONFIG["resetBufferMs"]:
                return {"canProceed": True, "waitMs": 0, "reason": "Past reset time"}
            
            safe_remaining = int(limit * (1 - RATE_LIMIT_CONFIG["safetyThreshold"]))
            
            if remaining <= safe_remaining:
                wait_ms = max(0, reset_time - now + RATE_LIMIT_CONFIG["resetBufferMs"])
                self.stats["throttledRequests"] += 1
                return {
                    "canProceed": False,
                    "waitMs": wait_ms,
                    "reason": f"Below safety threshold ({remaining}/{limit})"
                }
            
            if remaining <= 0:
                 wait_ms = max(0, reset_time - now + RATE_LIMIT_CONFIG["resetBufferMs"])
                 self.stats["throttledRequests"] += 1
                 return {
                    "canProceed": False,
                    "waitMs": wait_ms,
                    "reason": "Rate limit exhausted"
                 }

        return {"canProceed": True, "waitMs": RATE_LIMIT_CONFIG["minDelayMs"], "reason": "Within limits"}

    def request_started(self):
        self.active_requests += 1
        self.stats["totalRequests"] += 1
        self.request_history.append(time.time() * 1000)
        cutoff = (time.time() * 1000) - 60000
        self.request_history = [t for t in self.request_history if t > cutoff]

    def request_completed(self):
        self.active_requests = max(0, self.active_requests - 1)

    def record_rate_limit_hit(self, url: str, reset_time: Optional[int] = None):
        category = self.get_endpoint_category(url)
        self.stats["rateLimitHits"] += 1
        
        info = self.endpoints.get(category, {"limit": RATE_LIMIT_CONFIG["defaultLimit"]})
        info["remaining"] = 0
        info["resetTime"] = (reset_time * 1000) if reset_time else (time.time() * 1000 + 60000)
        info["lastUpdated"] = time.time() * 1000
        self.endpoints[category] = info

    def get_status(self):
        now = time.time() * 1000
        endpoint_status = {}
        
        for cat, info in self.endpoints.items():
            time_until_reset = max(0, info["resetTime"] - now)
            limit = info["limit"]
            remaining = info["remaining"]
            percent_used = ((limit - remaining) / limit) * 100
            
            endpoint_status[cat] = {
                "limit": limit,
                "remaining": remaining,
                "percentUsed": f"{percent_used:.1f}%",
                "resetsIn": f"{time_until_reset/1000:.1f}s",
                "resetTime": datetime_iso(info["resetTime"])
            }
            
        return {
            "concurrent": {
                "active": self.active_requests,
                "limit": RATE_LIMIT_CONFIG["concurrentLimit"],
                "available": RATE_LIMIT_CONFIG["concurrentLimit"] - self.active_requests
            },
            "requestsLastMinute": len(self.request_history),
            "endpoints": endpoint_status,
            "stats": self.stats,
            "config": RATE_LIMIT_CONFIG
        }

    def get_wait_time_for_429(self, headers: httpx.Headers) -> float:
        reset = headers.get("x-rate-limit-reset")
        if reset:
             reset_ms = int(reset) * 1000
             wait_ms = max(0, reset_ms - (time.time() * 1000) + RATE_LIMIT_CONFIG["resetBufferMs"])
             return wait_ms
        return 60000

def datetime_iso(ts_ms):
    return datetime.datetime.fromtimestamp(ts_ms/1000, datetime.timezone.utc).isoformat()

# Global Tracker
tracker = RateLimitTracker()

class OktaClient:
    def __init__(self):
        self.domain = os.environ.get("OKTA_DOMAIN")
        self.token = os.environ.get("OKTA_API_TOKEN")
        if not self.domain or not self.token:
            logger.error("OKTA_DOMAIN or OKTA_API_TOKEN not set!")
        
        self.headers = {
            "Authorization": f"SSWS {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    
    async def wait_for_rate_limit(self, url: str) -> float:
        check = tracker.can_make_request(url)
        if not check["canProceed"]:
            wait_ms = check["waitMs"]
            logger.info(f"[THROTTLE] Waiting {wait_ms/1000:.2f}s - {check['reason']}")
            await asyncio.sleep(wait_ms / 1000.0)
            return wait_ms
        
        if check["waitMs"] > 0:
            await asyncio.sleep(check["waitMs"] / 1000.0)
            return check["waitMs"]
        return 0

    async def execute_request(self, method: str, url: str, headers: dict = None, body: Any = None, params: dict = None):
        if not url.startswith("https://") and not url.startswith("http://"):
             url = f"https://{self.domain}{url}" if url.startswith("/") else f"https://{self.domain}/{url}"
        
        req_headers = self.headers.copy()
        if headers:
            req_headers.update(headers)
        
        tracker.request_started()
        
        async with httpx.AsyncClient() as client:
            try:
                logger.debug(f"[DEBUG] {method} {url}")
                response = await client.request(
                    method=method, 
                    url=url, 
                    headers=req_headers, 
                    json=body if body else None,
                    params=params
                )
                
                tracker.update_from_headers(url, response.headers)
                
                http_code = response.status_code
                
                if http_code == 429:
                    reset_time = response.headers.get("x-rate-limit-reset")
                    tracker.record_rate_limit_hit(url, int(reset_time) if reset_time else None)
                    wait_ms = tracker.get_wait_time_for_429(response.headers)
                    logger.error(f"[RATE LIMIT] 429 received - need to wait {wait_ms/1000:.1f}s")
                    
                    return {
                        "success": False,
                        "httpCode": str(http_code),
                        "response": _parse_json_safe(response),
                        "rateLimitWaitMs": wait_ms
                    }

                success = 200 <= http_code < 300
                if not success:
                    logger.error(f"[ERROR] HTTP {http_code}: {response.text}")
                
                return {
                    "success": success,
                    "httpCode": str(http_code),
                    "response": _parse_json_safe(response),
                    "headers": dict(response.headers)
                }

            except Exception as e:
                logger.error(f"[EXCEPTION] {str(e)}")
                return {
                    "success": False,
                    "httpCode": "EXCEPTION",
                    "error": str(e),
                    "response": {"errorSummary": str(e)}
                }
            finally:
                tracker.request_completed()

    async def execute_with_retry(self, method: str, url: str, headers: dict = None, body: Any = None):
        total_wait_ms = 0
        
        for attempt in range(RETRY_CONFIG["maxRetries"] + 1):
            if attempt == 0:
                waited = await self.wait_for_rate_limit(url)
                total_wait_ms += waited

            result = await self.execute_request(method, url, headers, body)
            
            if result["success"]:
                return result

            if result.get("httpCode") == "429":
                if attempt >= RETRY_CONFIG["maxRetries"]:
                    logger.error("Max retries exceeded for 429")
                    break
                
                wait_ms = result.get("rateLimitWaitMs", 0)
                if not wait_ms:
                    wait_ms = RETRY_CONFIG["baseDelayMs"] * (RETRY_CONFIG["backoffMultiplier"] ** attempt)
                    jitter = random.random() * 0.3 * wait_ms
                    wait_ms += jitter
                    wait_ms = min(wait_ms, RETRY_CONFIG["maxDelayMs"])
                
                logger.info(f"[RETRY] Waiting {wait_ms/1000:.2f}s before retry {attempt+1}")
                await asyncio.sleep(wait_ms / 1000.0)
                total_wait_ms += wait_ms
                continue
            
            return result
            
        return result

def _parse_json_safe(response):
    try:
        return response.json()
    except:
        return {"raw": response.text}

okta_client = OktaClient()
