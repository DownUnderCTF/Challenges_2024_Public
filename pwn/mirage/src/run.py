#!/usr/bin/env python3

from selenium import webdriver
import sys
from urllib.parse import urlparse
import time
import os

def visit_url(url):
    options = webdriver.ChromeOptions()
    options.binary_location = './chromium/chrome'

    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")

    service = webdriver.ChromeService(executable_path="./chromium/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)
    driver.get(url)

    time.sleep(5)


def validate_url(url):
    try:
        result = urlparse(url)
        return all([
            result.scheme == 'http' or result.scheme == 'https',
            result.netloc
        ])
    except AttributeError:
        return False


def main():
    os.chdir("/home/ctf/chal")
    print('url: ', end='')
    sys.stdout.flush()

    url = sys.stdin.readline()
    if validate_url(url):
        visit_url(url)


if __name__ == '__main__':
    main()
