import time
from urllib.parse import urlparse

from curl_cffi import requests

from awswaf import AwsWaf


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
    goku, host = AwsWaf.extract(response.text)

    start = time.time()
    token = AwsWaf(goku, host, urlparse(url).hostname)()
    end = time.time()

    internal_headers.update({"cookie": "aws-waf-token=" + token})
    solved = len(ses.get(url, headers=internal_headers, cookies=cookies).text) > 20000
    if solved:
        print(
            '[\x1b[32;1m+\x1b[0m] Solved: {} in {}s "{}"'.format(
                token, end - start, url
            )
        )
    else:
        print(f'failed to solve "{url}"!')


if __name__ == "__main__":
    session = requests.Session(impersonate="chrome")

    solve(session, "https://www.binance.com/")
