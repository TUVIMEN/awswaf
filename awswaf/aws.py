import random, json
from typing import Tuple
import re
from urllib.parse import urlparse

from curl_cffi import requests
from .verify import CHALLENGE_TYPES
from .fingerprint import get_fp


def extract(html: str) -> Tuple[dict, str]:
    goku_props = json.loads(html.split("window.gokuProps = ")[1].split(";")[0])
    endpoint = html.split('src="https://')[1].split("/challenge.js")[0]
    return goku_props, endpoint


def valid_token(token: str) -> bool:
    if len(token) > 5000:
        return False
    token = token.split(":")
    if len(token) != 3:
        return False
    uuid, middle, base64 = token

    if (
        re.fullmatch(
            r"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}",
            uuid,
        )
        is None
    ):
        return False

    if (
        re.fullmatch(
            r"[^ :]{16}",
            middle,
        )
        is None
    ):
        return False

    if (
        re.fullmatch(
            r"[-A-Za-z0-9+/]+={0,3}$",
            base64,
        )
        is None
    ):
        return False

    return True


def detect_challenge(response) -> bool:
    if response.status_code != 202:
        return False
    headers = response.headers
    if (x := headers.get("server")) is None or x != "CloudFront":
        return False
    if (x := headers.get("x-amzn-waf-action")) is None or x != "challenge":
        return False
    return True


def token(
    ses,
    goku_props: str,
    endpoint: str,
    domain: str,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
):
    def get_inputs():
        return ses.get(f"https://{endpoint}/inputs?client=browser").json()

    def build_payload(inputs: dict):
        verify_func = CHALLENGE_TYPES[inputs["challenge_type"]]
        checksum, fp = get_fp(user_agent)
        return {
            "challenge": inputs["challenge"],
            "checksum": checksum,
            "solution": verify_func(
                inputs["challenge"]["input"], checksum, inputs["difficulty"]
            ),
            "signals": [{"name": "Zoey", "value": {"Present": fp}}],
            "existing_token": None,
            "client": "Browser",
            "domain": domain,
            "metrics": [
                {"name": "2", "value": random.uniform(0, 1), "unit": "2"},
                {"name": "100", "value": 0, "unit": "2"},
                {"name": "101", "value": 0, "unit": "2"},
                {"name": "102", "value": 0, "unit": "2"},
                {"name": "103", "value": 8, "unit": "2"},
                {"name": "104", "value": 0, "unit": "2"},
                {"name": "105", "value": 0, "unit": "2"},
                {"name": "106", "value": 0, "unit": "2"},
                {"name": "107", "value": 0, "unit": "2"},
                {"name": "108", "value": 1, "unit": "2"},
                {"name": "undefined", "value": 0, "unit": "2"},
                {"name": "110", "value": 0, "unit": "2"},
                {"name": "111", "value": 2, "unit": "2"},
                {"name": "112", "value": 0, "unit": "2"},
                {"name": "undefined", "value": 0, "unit": "2"},
                {"name": "3", "value": 4, "unit": "2"},
                {"name": "7", "value": 0, "unit": "4"},
                {"name": "1", "value": random.uniform(10, 20), "unit": "2"},
                {"name": "4", "value": 36.5, "unit": "2"},
                {"name": "5", "value": random.uniform(0, 1), "unit": "2"},
                {"name": "6", "value": random.uniform(50, 60), "unit": "2"},
                {"name": "0", "value": random.uniform(130, 140), "unit": "2"},
                {"name": "8", "value": 1, "unit": "4"},
            ],
            # "goku_props": goku_props,
        }

    def verify(payload):
        ses.headers = {
            "connection": "keep-alive",
            "sec-ch-ua-platform": '"Windows"',
            "user-agent": user_agent,
            "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            "content-type": "text/plain;charset=UTF-8",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            # "origin": "https://www.binance.com",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            # "referer": "https://www.binance.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
        }

        res = ses.post(f"https://{endpoint}/verify", json=payload).json()
        return res["token"]

    inputs = get_inputs()
    payload = build_payload(inputs)
    return verify(payload)


def solve(session, response, url):
    goku, endpoint = extract(response.text)

    tk = token(session, goku, endpoint, urlparse(url).hostname)

    assert valid_token(tk)

    return {"aws-waf-token": tk}
