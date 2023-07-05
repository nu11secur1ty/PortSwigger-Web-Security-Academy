#!/usr/bin/python3
# Author: @nu11secur1ty
# Debug and Developement: @nu11secur1ty 

from selenium import webdriver
import time
import os


website_link="https://datafetcher.com/graphql-json-body-converter"


browser = webdriver.Chrome()
browser.get((website_link))	

try:
	browser.execute_script("document.querySelector('[name=\"GraphQL Query\"]').value=\"Paste your payload here ;)\"")

	print("After you'll ready please put \"query\":\"mutation{" " on the first line, and on the latest line, close with } before \"")
	print("Your conversion is done")
	input("Press Enter to close the browser")
	
except Exception:
	#### This exception occurs if the element are not found in the webpage.
	print("Some error occured :(")
