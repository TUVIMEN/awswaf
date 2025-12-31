#!/usr/bin/env python

import sys
import time
import re
from urllib.parse import urlparse

from curl_cffi import requests

from awswaf import AwsWaf

DEBUG = False


class Success(Exception):
    pass


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


def test(func):
    def wrapper(*args, **kwargs):
        if DEBUG:
            return func(*args, **kwargs)

        try:
            ret = func(*args, **kwargs)
        except Success as e:
            print(e.args[0])
        except Exception as e:
            print(repr(e), file=sys.stderr)
        else:
            return ret

    return wrapper


@test
def solve(ses, url, headers={}, cookies={}):
    internal_headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "cache-control": "no-cache",
        #'dnt': '1',
        "pragma": "no-cache",
        "priority": "u=0, i",
        "sec-ch-ua": '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "sec-gpc": "1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    }
    internal_headers.update(headers)

    response = ses.get(url, headers=internal_headers, cookies=cookies)
    assert detect_challenge(response)

    goku, host = AwsWaf.extract(response.text)

    start = time.time()
    token = AwsWaf(goku, host, urlparse(url).hostname)()
    end = time.time()

    assert valid_token(token)

    internal_headers.update({"cookie": "aws-waf-token=" + token})

    nresponse = ses.get(url, headers=internal_headers, cookies=cookies)
    if detect_challenge(nresponse):
        raise Exception(f'failed to solve "{url}"!')

    raise Success(
        '[\x1b[32;1m+\x1b[0m] Solved: \x1b[35m{}\x1b[0m in \x1b[33m{}s\x1b[0m "\x1b[34m{}\x1b[0m"'.format(
            token, round(end - start, 3), url
        )
    )


if __name__ == "__main__":
    session = requests.Session(impersonate="chrome")

    solve(session, "https://www.binance.com/")
    solve(
        session,
        "https://news.hrvh.org/veridian/?a=d&d=ieadbehj19440627.1.5&e=-------en-20--1--txt-txIN-------",
    )
