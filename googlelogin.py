import sys
import re
import netrc
import logging
import argparse

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from PatchedMozillaCookieJar import MozillaCookieJar

__all__ = ['Session', 'get_session']

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARN)


def setup_webdriver():
    driver = webdriver.PhantomJS()
    driver.set_window_size(1120, 550)  # https://realpython.com/blog/python/headless-selenium-testing-with-python-and-phantomjs/
    return driver


def copy_cookies_to_session(driver, session):
    """Copy cookies from selenium webdriver to requests.Session"""
    cookies = driver.get_cookies()
    for cookie in cookies:
        session.cookies.set(
            cookie['name'],
            cookie['value'],
            domain=cookie['domain'],
            path=cookie['path']
        )


class Session(requests.Session):
    """A Google session"""

    def __init__(self, *args, **kwargs):
        super(Session, self).__init__(*args, **kwargs)
        self.url = "https://console.developers.google.com"

    def find_sign_in(self, driver):
        conditions = [
            EC.presence_of_element_located((By.PARTIAL_LINK_TEXT, "Sign in")),
            EC.presence_of_element_located((By.PARTIAL_LINK_TEXT, "SIGN IN")),
        ]
        for condition in conditions:
            try:
                sign_in = WebDriverWait(driver, 5).until(condition)
            except:
                pass
            else:
                break
        return sign_in

    def login(self, username, password, url=None):
        if url is not None:
            self.url = url
        driver = setup_webdriver()
        try:
            driver.get(self.url)
            driver.find_element_by_id("Email").clear()
            driver.find_element_by_id("Email").send_keys(username)
            try:
                driver.find_element_by_id("Passwd").clear()
                driver.find_element_by_id("Passwd").send_keys(password)
            except:
                driver.find_element_by_id("next").click()
                condition = EC.visibility_of_element_located((By.ID, "Passwd"))
                passwd = WebDriverWait(driver, 5).until(condition)
                passwd.clear()
                passwd.send_keys(password)
            driver.find_element_by_id("signIn").click()
            copy_cookies_to_session(driver, self)
        except:
            driver.save_screenshot('/tmp/googlelogin_problem.png')
            raise
        finally:
            driver.quit()

    def is_logged_in(self):
        response = self.get(self.url, allow_redirects=False)
        if response.status_code == 302:
            login_url = "https://accounts.google.com/ServiceLogin"
            return not response.headers['location'].startswith(login_url)
        else:
            return response.status_code == 200

    def save(self, filename):
        cj = MozillaCookieJar(filename)
        for cookie in self.cookies:
            cj.set_cookie(cookie)
        cj.save(ignore_discard=True, ignore_expires=True)

    def load(self, filename):
        cj = MozillaCookieJar(filename)
        cj.load(ignore_discard=True, ignore_expires=True)
        for cookie in cj:
            self.cookies.set_cookie(cookie)


def get_session(cookies_path="cookies.txt", url=None):
    username, _, password = netrc.netrc().authenticators("google.com")
    session = Session()
    logger.debug("trying to load saved session")
    try:
        session.load(cookies_path)
    except IOError:
        logger.debug("error loading saved session")
        logger.debug("logging in")
        session.login(username, password, url=url)
        session.save(cookies_path)
    else:
        logger.debug("loaded saved session")
        logger.debug("are we still logged in?")
        if not session.is_logged_in():
            logger.debug("no so logging in")
            session.login(username, password, url=url)
            logger.debug("saving session")
            session.save(cookies_path)
        else:
            logger.debug("yup, we're still logged in")
    return session


def main(argv=None):
    if argv is None:
        argv = sys.argv
    parser = argparse.ArgumentParser(description='Login to Google')
    parser.add_argument('cookies_path', help="path for cookies.  usually cookies.txt")
    parser.add_argument('--url', help="URL of Google resource you're trying to access")
    args = parser.parse_args(argv[1:])
    session = get_session(args.cookies_path, url=args.url)


if __name__ == '__main__':
    sys.exit(main())
