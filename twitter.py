import time
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

def authenticate():
    CONSUMER_KEY = os.environ.get('CONSUMER_KEY')
    CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')

    if CONSUMER_KEY is None or CONSUMER_SECRET is None:
        print('CONSUMER_KEY or CONSUMER_SECRET cannot be none')
    else:
        ACCESS_TOKEN = os.environ.get('ACCESS_TOKEN')
        ACCESS_SECRET = os.environ.get('ACCESS_SECRET')
        if (ACCESS_TOKEN is not None) and (ACCESS_SECRET is not None):
            return CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_SECRET
    
    request_token_url = 'https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write'
    oauth = OAuth1Session(CONSUMER_KEY, client_secret=CONSUMER_SECRET)
    fetch_response = oauth.fetch_request_token(request_token_url)
    
    resource_owner_key = fetch_response.get('oauth_token')
    resource_owner_secret = fetch_response.get('oauth_token_secret')

    base_authorization_url = 'https://api.twitter.com/oauth/authorize'
    authorization_url = oauth.authorization_url(base_authorization_url)

    print('Please go here and authorize: ', authorization_url)
    verifier = input('Paste the PIN here: ')

    # Get the access token
    access_token_url = 'https://api.twitter.com/oauth/access_token'
    oauth = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            verifier=verifier
            )
    oauth_tokens = oauth.fetch_access_token(access_token_url)
    
    access_token = oauth_tokens['oauth_token']
    access_secret = oauth_tokens['oauth_token_secret']

    # Save the credentials to file
    with open('.env', 'w', encoding='utf-8') as file:
        file.write(f'CONSUMER_KEY={CONSUMER_KEY}\n')
        file.write(f'CONSUMER_SECRET={CONSUMER_SECRET}\n')
        file.write(f'ACCESS_TOKEN={access_token}\n')
        file.write(f'ACCESS_SECRET={access_secret}')
    
    return CONSUMER_KEY, CONSUMER_SECRET, access_token, access_secret

def refresh_token(consumer_key, consumer_secret, access_token, access_secret_token):
    refresh_url = 'https://api.twitter.com/oauth/request_token'
    oauth = OAuth1Session(
            consumer_key,
            client_secret=consumer_secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=access_token_secret,
            )
    response = oauth.post(refresh_url, data={'grant_type': 'client_credentials'})
    if response.status_code == 200:
        new_access_token = response.json().get('access_token')

        with open('.env', 'w', encoding='utf-8') as file:
            file.write(f'CONSUMER_KEY={consumer_key}\n')
            file.write(f'CONSUMER_SECRET={consumer_secret}\n')
            file.write(f'ACCESS_TOKEN={new_access_token}\n')
            file.write(f'ACCESS_SECRET={access_token_secret}')   
        return consumer_key, consumer_secret, new_access_token, access_secret_token
    else:
       print('Failed to referesh token', response)
       return None

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

consumer_key, consumer_secret, access_token, access_token_secret = authenticate()

client = tweepy.Client(consumer_key=consumer_key, consumer_secret=consumer_secret, access_token=access_token, access_token_secret=access_token_secret)

while True:
    url = 'https://camo.githubusercontent.com/ee6d0eb34e7d561d98c8e17ead480ff34d1b75e952ea4327086698d4791c9db6/68747470733a2f2f726561646d652d6a6f6b65732e76657263656c2e6170702f6170693f7468656d653d64656661756c74'

    try:
        
        text = get_text_from_url(url)
        response = client.create_tweet(text=text)   
    
        print("Tweet posted. Tweet ID:", response.data['id'])
        time.sleep(interval_seconds)
    except Exception as e:
        if 'expired' in str(e):
            refresh_token(consumer_key, consumer_secret, access_token, access_secret_token)
            continue
        elif 'limit' in str(e):
            time.sleep((60 * 6) * 24)
        elif 'duplicate' in str(e):
            continue
        else:
            print("Error posting tweet:", e)
        continue
