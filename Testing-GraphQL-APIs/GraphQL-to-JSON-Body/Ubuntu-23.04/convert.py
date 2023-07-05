#!/usr/bin/python3
# Author: @nu11secur1ty
# Debug and Developement: @nu11secur1ty 

from selenium import webdriver
import time
import os
from selenium.webdriver.chrome.service import Service

service = Service(executable_path="chromedriver")
with webdriver.Chrome(service=service) as driver:

    driver.get('https://datafetcher.com/graphql-json-body-converter')
    print("Paste your payload in GraphQL Query section")
    print("After you'll ready please put \"query\":\"mutation{" " on the first line, and on the latest line, close with } before \" into your already saved file")
    print("Then, press Enter to close the browser")
    input()

try:

    print("Done")

except Exception:
	#### This exception occurs if the element are not found in the webpage.
	print("Some error occured :(")
