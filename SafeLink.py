# Import necessary libraries and modules
import os
import logging
import discord
import re
import requests
import asyncio
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables from .env file
load_dotenv()
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Set up logging for monitoring bot activities
logging.basicConfig(level=logging.INFO)

# Define Discord intents for the bot
intents = discord.Intents.default()
intents.message_content = True

# Initialize Discord client with specified intents
client = discord.Client(intents=intents)

# Define specific channel IDs where the bot will operate
SPECIFIC_CHANNEL_ID = [1139673753115164716, 1184784642444902400]

# Define moderator IDs for alerting in case of rule violations
MODERATOR_IDS = [921065510429417542]  # Replace with actual moderator IDs

# Function to check if a URL is from a short URL service
def is_short_url(url):
    # List of known short URL services
    short_url_services = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly", "discord.gg", "web.app",
        "shorturl.at", "is.gd", "so.gd", "s.coop", "q.gs", "zpr.io",
        "rebrand.ly", "shorte.s", "youtu.be", "wp.me", "rb.gy", "cutt.ly"
    ]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return any(domain.endswith(service) for service in short_url_services)

# Function to extract domain from a URL
def get_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

# Event handler for when the bot is ready
@client.event
async def on_ready():
    logging.info(f'Logged in as {client.user}')

# Event handler for processing messages
@client.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == client.user:
        return
        
    # Process messages only in specified channels
    if message.channel.id not in SPECIFIC_CHANNEL_ID:
        return

    # Regex to find URLs in the message
    url_regex = r'https?://[^\s]+'
    urls = re.findall(url_regex, message.content)

    # Check each URL in the message
    if urls:
        for url in urls:
            # Notify moderators for review
            if is_short_url(url):
                moderator_mentions = ' '.join(f'<@{mod_id}>' for mod_id in MODERATOR_IDS)
                warning_msg = (
                    "🚨 Short URLs are not allowed. Please refrain from using short links.\n\n"
                    f"{moderator_mentions}, please review this message for appropriate action against the user: {message.author.mention} (ID: {message.author.id})."
                )
                await message.reply(warning_msg)
                await message.delete()
                continue  # Move to the next URL

            # Handling regular URLs using VirusTotal API
            domain = get_domain_from_url(url)
            logging.info(f'Checking domain: {domain}')

            # API call to VirusTotal
            virustotal_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
            response = requests.get(virustotal_url, headers=headers)

            # Process VirusTotal response
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)

                # If malicious links are detected
                if malicious_count > 0:
                    stats = f"Malicious: {malicious_count}, Harmless: {last_analysis_stats.get('harmless', 0)}, Undetected: {last_analysis_stats.get('undetected', 0)}"
                    warning_message = (
                        f"**⚠️ Attention:** \n"
                        "This link is potentially dangerous and may be part of a cryptocurrency scam.\n"
                        "Be aware that sharing such links is against server rules and can lead to legal consequences.\n"
                        "All suspicious activities are monitored and may be reported to law enforcement.\n\n"
                        f"<@{MODERATOR_IDS[0]}>, please review this message for appropriate action against the user who has posted the malicious link: {message.author.mention} (ID: {message.author.id}).\n\n"
                        f"🔍 **VirusTotal stats:**\n{stats}."
                    )
                    await message.reply(warning_message)
                    await message.add_reaction("❌")
                    await asyncio.sleep(5)
                    await message.delete()
            else:
                logging.error(f'Error fetching VirusTotal API response for domain {domain}. Status code: {response.status_code}')

client.run(DISCORD_TOKEN)
