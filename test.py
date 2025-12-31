#!/usr/bin/env python

import sys
import time

import curl_cffi
import requests

import awswaf

DEBUG = True


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
    response = ses.get(url, headers=headers, cookies=cookies)
    assert awswaf.detect_challenge(response)

    start = time.time()
    token = awswaf.solve(ses, response, url)
    end = time.time()

    cookies.update(token)
    token = token["aws-waf-token"]

    nresponse = ses.get(url, headers=headers, cookies=cookies)
    if awswaf.detect_challenge(nresponse):
        raise Exception(f'failed to solve "{url}"!')

    print(
        '[\x1b[32;1m+\x1b[0m] Solved: \x1b[35m{}\x1b[0m in \x1b[33m{}s\x1b[0m "\x1b[34m{}\x1b[0m"'.format(
            token, round(end - start, 3), url
        )
    )


@test
def solve_wrap(url, sessioninit):
    session = sessioninit()
    awswaf.session_wrap(session)
    # try:
    response = session.get(url)
    # except awswaf.Error:
    # raise Exception(f'failed to solve "{url}"!')

    if awswaf.detect_challenge(response):
        raise Exception(f'failed to solve "{url}"!')
    print(f'[\x1b[32;1m+\x1b[0m] Solved "{url}"')


def test_lib(sessioninit):
    session = sessioninit()
    solve(session, "https://www.binance.com/")
    solve(
        session,
        "https://news.hrvh.org/veridian/?a=d&d=ieadbehj19440627.1.5&e=-------en-20--1--txt-txIN-------",
    )

    solve_wrap("https://www.binance.com/", sessioninit)
    solve_wrap(
        "https://news.hrvh.org/veridian/?a=d&d=ieadbehj19440627.1.5&e=-------en-20--1--txt-txIN-------",
        sessioninit,
    )


if __name__ == "__main__":

    def createsession(session):
        ses = session()
        ses.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
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
        )
        return lambda: ses

    print("Testing curl_cffi lib")
    test_lib(lambda: curl_cffi.requests.Session(impersonate="chrome"))

    print("Testing requests lib")
    test_lib(createsession(requests.Session))
