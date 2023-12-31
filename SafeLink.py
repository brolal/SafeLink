import os
import logging
import discord
import re
import hashlib
import requests
import asyncio
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Set up logging
logging.basicConfig(level=logging.INFO)

# Define intents
intents = discord.Intents.default()
intents.message_content = True

# Initialize Discord client with intents
client = discord.Client(intents=intents)

# Define the specific channel IDs
SPECIFIC_CHANNEL_ID = [1139673753115164715, 1184784642444902409]

# Define the moderator IDs
MODERATOR_IDS = [921065510429417541]  # Replace with actual moderator IDs

def is_short_url(url):
    # List of known short URL services
    short_url_services = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
        "shorturl.at", "is.gd", "so.gd", "s.coop", "q.gs", "zpr.io",
        "rebrand.ly", "shorte.s", "youtu.be", "wp.me", "rb.gy", "cutt.ly"
    ]
    return any(service in url for service in short_url_services)

@client.event
async def on_ready():
    logging.info(f'Logged in as {client.user}')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.channel.id not in SPECIFIC_CHANNEL_ID:
        return

    url_regex = r'https?://[^\s]+'
    urls = re.findall(url_regex, message.content)

    if urls:
        for url in urls:
            if is_short_url(url):
                # Create a string that mentions all moderators
                moderator_mentions = ' '.join(f'<@{mod_id}>' for mod_id in MODERATOR_IDS)
                warning_msg = (
                    "Short URLs are not allowed. Please refrain from using short links.\n\n"
                    f"{moderator_mentions}, please review this message for appropriate action against the user: {message.author.mention} (ID: {message.author.id})."
                )
                await message.reply(warning_msg)
                await message.delete()
                return  # Stop processing more URLs

            # Check with VirusTotal
            logging.info(f'URL found: {url}')
            url_sha256 = hashlib.sha256(url.encode()).hexdigest()

            virustotal_url = f"https://www.virustotal.com/api/v3/urls/{url_sha256}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
            response = requests.get(virustotal_url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)

                if malicious_count > 0:
                    stats = f"Malicious: {malicious_count}, Harmless: {last_analysis_stats.get('harmless', 0)}, Undetected: {last_analysis_stats.get('undetected', 0)}"
                    warning_message = (
                        f"**⚠️ Attention:** \n" 
                        "This link is potentially dangerous and may be part of a cryptocurrency scam.\n"
                        "Be aware that sharing such links is against server rules and can lead to legal consequences.\n"
                        "All suspicious activities are monitored and may be reported to law enforcement.\n\n"
                        f"<@921065510429417542>, please review this message for appropriate action against the user who has posted the malicious link: {message.author.mention} (ID: {message.author.id}).\n\n"
                        f"🔍 **VirusTotal stats:**\n{stats}."
                    )
                    await message.reply(warning_message)
                    await message.add_reaction("❌")
                    await asyncio.sleep(5)
                    await message.delete()

                logging.info(f'VirusTotal API response for {url}: {response.text}')
            else:
                logging.error(f'Error fetching VirusTotal API response for {url}. Status code: {response.status_code}')

client.run(DISCORD_TOKEN)
