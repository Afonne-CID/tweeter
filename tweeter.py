import os
import json
import time
import base64
import requests
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
from bs4 import BeautifulSoup

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


def authenticate_v2():
    CREDENTIALS_FILE = 'twitter_credentials.json'
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as file:
            cred = json.load(file)
            return cred['CONSUMER_KEY'], cred['CONSUMER_SECRET'], cred['USER_CONTEXT_TOKEN']
                                                    
    CONSUMER_KEY = os.environ.get('CONSUMER_KEY')
    CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')

    if CONSUMER_KEY is None or CONSUMER_SECRET is None:
        print('CONSUMER_KEY or CONSUMER_SECRET cannot be None')

    user_context_token = get_user_context_token(CONSUMER_KEY, CONSUMER_SECRET)

    if user_context_token:
        save_user_context_token(CREDENTIALS_FILE, CONSUMER_KEY, CONSUMER_SECRET, user_context_token)
        return CONSUMER_KEY, CONSUMER_SECRET, user_context_token

def get_user_context_token(CONSUMER_KEY, CONSUMER_SECRET):
    USER_CONTEXT_ENDPOINT = 'https://api.twitter.com/oauth2/token'
    
    bearer_credentials = f'{CONSUMER_KEY}:{CONSUMER_SECRET}'
    base64_encoded_credentials = base64.b64encode(bearer_credentials.encode('utf-8')).decode('utf-8')

    headers = {
            'Authorization': f'Basic {base64_encoded_credentials}',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            }

    data = {
            'grant_type': 'client_credentials'
            }

    response = requests.post(USER_CONTEXT_ENDPOINT, headers=headers, data=data)

    if response.status_code == 200:
          return response.json().get('access_token')
    else:
        print(f'Failed to authenticate. Status code: {response.status_code}')
        return None

def save_user_context_token(file_path, CONSUMER_KEY, CONSUMER_SECRET, user_context_token):
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump({
            'CONSUMER_KEY': CONSUMER_KEY,
            'CONSUMER_SECRET': CONSUMER_SECRET,
            'USER_CONTEXT_TOKEN': user_context_token
            }, file)

def post_tweet_v2(tweet_text):
    TWEET_ENDPOINT = 'https://api.twitter.com/2/tweets'
    api_key, api_secret_key, user_context_token = authenticate_v2()
    
    headers = {
                                                                                 'Authorization': f'Bearer {user_context_token}',
                                                                                 'Content-Type': 'application/json',
                                                                                 }

    tweet_data = {
            'status': tweet_text
            }
    
    response = requests.post(TWEET_ENDPOINT, headers=headers, json=tweet_data)
    
    if response.status_code == 201:
        print('Tweet posted successfully!')
    else:
       print(f'Failed to post tweet. Status code: {response.status_code}\n{response.text}')

    return response

def post_tweet(url):
    consumer_key, consumer_secret, access_token, access_secret = authenticate()
    text = url#get_text_from_url(url)
    tweet_url = 'https://api.twitter.com/2/tweets'
    tweet_params = {'tweet.fields': text}

    auth = OAuth1Session(
                    consumer_key,
                    client_secret=consumer_secret,
                    resource_owner_key=access_token,
                    resource_owner_secret=access_secret
                   )

    response = auth.post(tweet_url, params=tweet_params)

    if response.status_code == 200:
        print('Tweet posted successfully!')
        return response
    else:
        print(f'Failed to tweet. {response.text}\n Status code: {response.status_code}')
        return response

def authenticate():
    CREDENTIALS_FILE = 'twitter_credentials.json'
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as file:
            cred = json.load(file)
            return cred['CONSUMER_KEY'], cred['CONSUMER_SECRET'], cred['ACCESS_TOKEN'], cred['ACCESS_SECRET']

    CONSUMER_KEY = os.environ.get('CONSUMER_KEY')
    CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')

    if CONSUMER_KEY is None or CONSUMER_SECRET is None:
        print('CONSUMER_KEY or CONSUMER_SECRET cannot be none')
    
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
    with open(CREDENTIALS_FILE, 'w', encoding='utf-8') as file:
        json.dump({
                'CONSUMER_KEY': CONSUMER_KEY,
                'CONSUMER_SECRET': CONSUMER_SECRET,
                'ACCESS_TOKEN': access_token,
                'ACCESS_SECRET': access_secret
            }, file)
    return CONSUMER_KEY, CONSUMER_SECRET, access_token, access_secret

target_executions = 1500
interval_seconds = 30 * 60

for _ in range(target_executions):
    url = 'https://camo.githubusercontent.com/ee6d0eb34e7d561d98c8e17ead480ff34d1b75e952ea4327086698d4791c9db6/68747470733a2f2f726561646d652d6a6f6b65732e76657263656c2e6170702f6170693f7468656d653d64656661756c74'

    response = post_tweet('Tweeted')
    if response.status_code != 201:
        break
    time.sleep(interval_seconds)
