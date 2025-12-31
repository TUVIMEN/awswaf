#!/usr/bin/env python

import sys
import time

from curl_cffi import requests

import awswaf

DEBUG = False


def test(func):
    def wrapper(*args, **kwargs):
        if DEBUG:
            return func(*args, **kwargs)

        try:
            ret = func(*args, **kwargs)
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
    }

    response = ses.get(url, headers=internal_headers, cookies=cookies)
    assert awswaf.detect_challenge(response)

    start = time.time()
    token = awswaf.solve(ses, response, url)
    end = time.time()

    cookies.update(token)
    token = token["aws-waf-token"]

    nresponse = ses.get(url, headers=internal_headers, cookies=cookies)
    if awswaf.detect_challenge(nresponse):
        raise Exception(f'failed to solve "{url}"!')

    print(
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
