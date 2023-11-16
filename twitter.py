import os
import requests
import tweepy
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

def get_text_from_url(url):
    try:
        # Fetch the HTML content of the URL
        response = requests.get(url)
        response.raise_for_status()

        # Parse HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract text
        text = soup.get_text()
        return text
    
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

consumer_key = os.environ.get('CONSUMER_KEY')
consumer_secret = os.environ.get('CONSUMER_SECRET')
access_token = os.environ.get('ACCESS_TOKEN')
access_token_secret = os.environ.get('ACCESS_SECRET')

def get_text_from_url(url):
    try:
        # Fetch the HTML content of the URL
        response = requests.get(url)
        response.raise_for_status()

        # Parse HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract text
        text = soup.get_text()
        return text
    
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

target_executions = 1500
interval_seconds = 30 * 60

client = tweepy.Client(consumer_key=consumer_key, consumer_secret=consumer_secret, access_token=access_token, access_token_secret=access_token_secret)

for _ in range(target_executions):
    url = 'https://camo.githubusercontent.com/ee6d0eb34e7d561d98c8e17ead480ff34d1b75e952ea4327086698d4791c9db6/68747470733a2f2f726561646d652d6a6f6b65732e76657263656c2e6170702f6170693f7468656d653d64656661756c74'

    text = get_text_from_url(url)
    response = client.create_tweet(text=text)   
    
    if response.status_code != 201:
        break
    time.sleep(interval_seconds)
