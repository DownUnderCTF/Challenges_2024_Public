import requests
import logging, os, time
from queue import Queue

bot_queue = Queue(maxsize=5)
APP_URL = os.environ.get("APP_URL", "http://waifu-app:3000")
XSSBOT_URL = os.getenv('XSSBOT_URL', 'http://xss-bot')
logging.basicConfig(level=logging.INFO)

def visit_url(url_path: str):
    driver = None
    try:
        logging.info("initiating bot")
        requests.post(f'{XSSBOT_URL}/visit', json={
            "url": f"{APP_URL}{url_path}"
        }, headers={
            'X-SSRF-Protection': '1'
        })
    except Exception as e:
        logging.error(e)
        pass
    finally:
        if not driver is None:
            driver.quit()
        logging.info("done")


def bot_worker():
    while True:
        try:
            url = bot_queue.get()[0]
            visit_url(url)
            bot_queue.task_done()
        except Exception as e:
            logging.error(e)

        # Only process 1 URL path every 5 minutes
        time.sleep(60*5)
