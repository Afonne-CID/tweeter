import random
import time
import os
import hashlib
import requests
import asyncio
from jokeapi import Jokes
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


async def the_joke():
    source = await Jokes()
    joke = await source.get_joke(category=["programming"])
    
    def split_into_chunks(text):
        # Split the text into chunks with complete sentences
        chunks = []
        words = text.split()
        current_chunk = words[0]

        for word in words[1:]:
            if len(current_chunk) + len(word) + 1 <= 279:  # +1 for space
                current_chunk += ' ' + word
            else:
                chunks.append(current_chunk)
                current_chunk = word

        # Add the last chunk
        chunks.append(current_chunk)

        return chunks

    if joke["type"] == "single":
        if len(joke["joke"]) >= 279:
            return split_into_chunks(joke["joke"])
        return [joke["joke"]]

    double_joke = joke["setup"] + "\n\n" + joke["delivery"]
    if len(double_joke) >= 279:
        return split_into_chunks(double_joke)
    return [double_joke]


def save_hash(string_hash, hashed_values_set):
    with open(hashes_file_path, 'w') as file:
        for hashed_value in hashed_values_set:
            file.write(f"{hashed_value}\n")
        file.write(f"{string_hash}\n")

def load_hashes():
    hashes_set = set()
    if os.path.exists(hashes_file_path):
        with open(hashes_file_path, 'r') as file:
            hashes_set.update(line.strip() for line in file)
    return hashes_set

def is_duplicate(string_hash):
    hashed_values_set = load_hashes()
    return string_hash in hashed_values_set

def hash_string(input_string):
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode('utf-8'))
    return sha256.hexdigest()

interval_seconds = 30 * 60
hashes_file_path = 'hashes.txt'

consumer_key, consumer_secret, access_token, access_token_secret = authenticate()

client = tweepy.Client(consumer_key=consumer_key, consumer_secret=consumer_secret, access_token=access_token, access_token_secret=access_token_secret)

while True:

    print('Enters infinite loop')

    url = 'https://camo.githubusercontent.com/ee6d0eb34e7d561d98c8e17ead480ff34d1b75e952ea4327086698d4791c9db6/68747470733a2f2f726561646d652d6a6f6b65732e76657263656c2e6170702f6170693f7468656d653d64656661756c74'

    try:

        tweets = []
        while True:
            frt_text = asyncio.run(the_joke())
            scnd_text = get_text_from_url(url)
            tweets = [[scnd_text], frt_text]
            tweets = tweets[random.randint(0, 1)]
            hashed = hash_string(tweets[0])
            
            if is_duplicate(hashed):
                continue
            else:
                break
        tweet = tweets[0]
        
        response = client.create_tweet(text=tweet)
        tweet_id = response.data['id']
        hashed_tweets = load_hashes()
        save_hash(hashed, hashed_tweets)
        for tweet in tweets[1:]:
            next_hashed = hash_string(tweet)
            if not is_duplicate(next_hashed):
                response = client.create_tweet(text=tweet, in_reply_to_tweet_id=tweet_id)
                tweet_id = response.data['id']
                tweet_hashes = load_hashes()
                save_hash(next_hashed, tweet_hashes)
            else:
                continue

            print("Tweet posted. Tweet ID:", response.data['id'])

        time.sleep(interval_seconds)

    except KeyError as e:
        os.remove('output.log')
        pass
    except Exception as e:
        if 'expired' in str(e).lower():
            os.remove('output.log')
            refresh_token(consumer_key, consumer_secret, access_token, access_secret_token)
            print('Error posting tweet, but refeshed expired token')
        elif 'limit' in str(e).lower() or 'too many' in str(e).lower():
            os.remote('output.log')
            print("2hrs sleet\tError posting tweet, limit reached or too mnay requests\n", e)
            time.sleep((60 * 60) * 2)
        elif 'duplicate' in str(e).lower():
            os.remove('output.log')
            print('Duplicate spotted, skipping that')
            dup_tweets = load_hashes()
            save_hash(hash_string(tweet), dup_tweets)
            time.sleep(5 * 60)
        else:
            raise e
            break
