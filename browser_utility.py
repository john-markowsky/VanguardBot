from playwright.async_api import async_playwright
import time
import logging
import sys
import os
import json
import asyncio

logging.basicConfig(level=logging.INFO, stream=sys.stderr)

# Dictionary to store browser and page objects for each user
user_sessions = {}

async def initialize_browser():
    p = await async_playwright().start()
    browser = await p.chromium.launch(headless=True)
    return browser

async def initialize_vanguard_login(user_id: str, username: str, password: str) -> dict:
    browser = await initialize_browser()
    page = await browser.new_page()
    
    # Store the browser and page objects for the user
    user_sessions[user_id] = {'browser': browser, 'page': page}

    try:
        logging.info("Initiating Vanguard login process...")
        await page.goto('https://logon.vanguard.com/logon')
        logging.info("Entering provided user credentials...")
        await page.fill('#USER', username)
        await page.fill('#PASSWORD-blocked', password)
        logging.info("Taking a screenshot after entering credentials...")
        await page.screenshot(path='after_credentials.png')
        logging.info("Submitting login form...")
        await page.click('span.c11n-button__label')
        
        logging.info("Waiting for 2FA method choice...")
        two_fa_method_choice_selector = "div.card-content.c11n-text-lg.text-align-left.card-button-padding"
        await page.wait_for_selector(two_fa_method_choice_selector, timeout=20000)
        
        logging.info("Clicking the 2FA method choice...")
        await page.click(two_fa_method_choice_selector)
        
        logging.info("Waiting for 2FA input...")
        two_fa_input_selector = '#CODE'
        await page.wait_for_selector(two_fa_input_selector, timeout=20000)
        
        cookies = await page.context.cookies()
        logging.info("Cookies obtained from Vanguard login process.")
        
        result = {"status": "awaiting_2fa", "cookies": json.dumps(cookies)}
        return result
    
    except Exception as e:
        logging.error(f"An error occurred during login initialization: {e}")
        return {"status": "error", "message": "An error occurred during login initialization."}

async def complete_vanguard_2fa(user_id: str, two_fa_code: str) -> dict:
    # Retrieve the browser and page objects for the user
    browser = user_sessions[user_id]['browser']
    page = user_sessions[user_id]['page']

    try:
        logging.info("Entering provided 2FA code...")
        two_fa_input_selector = '#CODE'
        await page.fill(two_fa_input_selector, two_fa_code)
        logging.info("Clicking to verify 2FA...")
        await page.click('span.c11n-button__label:has-text("Verify")')
        
        result = {"status": "success"}
        return result

    finally:
        # Optionally close the browser or keep it open
        pass
