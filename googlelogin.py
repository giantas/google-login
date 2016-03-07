import sys
import re
import netrc
import logging

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

    def login(self, username, password):
        driver = setup_webdriver()
        try:
            url = "https://accounts.google.com/login"
            driver.get(url)
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
        url = "https://myaccount.google.com/"
        response = self.get(url)
        return not "Sign in" in response.text

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


def get_session(cookies_path="cookies.txt"):
    username, _, password = netrc.netrc().authenticators("google.com")
    session = Session()
    logger.debug("trying to load saved session")
    try:
        session.load(cookies_path)
    except IOError:
        logger.debug("error loading saved session")
        logger.debug("logging in")
        session.login(username, password)
        session.save(cookies_path)
    else:
        logger.debug("loaded saved session")
        logger.debug("are we still logged in?")
        if not session.is_logged_in():
            logger.debug("no so logging in")
            session.login(username, password)
            logger.debug("saving session")
            session.save(cookies_path)
        else:
            logger.debug("yup, we're still logged in")
    return session


def main(argv=None):
    if argv is None:
        argv = sys.argv
    cookies_path = argv[1]
    session = get_session(cookies_path)


if __name__ == '__main__':
    sys.exit(main())
