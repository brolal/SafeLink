import requests

def send_poll(webhook_url, title, bot_info, vote_message):
    """
    Send a poll to the specified Discord channel via webhook.

    Args:
    webhook_url (str): The Discord webhook URL.
    title (str): The title of the poll.
    bot_info (str): Detailed information about the bot.
    vote_message (str): The message for voting options.
    """
    # Formatting the message
    formatted_message = f"**{title}**\n```{bot_info}```\n{vote_message}"

    # The data to be sent to Discord
    data = {
        "content": formatted_message,
        "username": "Opinion Poll"
    }

    result = requests.post(webhook_url, json=data)

    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(f"Error sending message: {err}")
    else:
        print("Message sent successfully.")

# Replace this with your Discord webhook URL
webhook_url = "your_webhook"

# Title for the poll
title = "Polling-tracker proposal #009 by <@921065510429417542>"

# Detailed information about the SafeLink bot
bot_info = (
    "About the Bot:\n"
    "    SafeLink is a Discord bot designed to enhance the digital security of our community. "
    "It automatically scans URLs shared in messages using the VirusTotal API, a renowned tool "
    "for analyzing and detecting potential security threats.\n\n"
    "What the Bot Does:\n"
    "    URL Scanning: The bot scans each URL posted in the server and checks it against the VirusTotal "
    "database for any known security threats.\n"
    "    Real-Time Alerts: If a link is identified as potentially malicious, the bot immediately warns "
    "users with a cautionary message.\n"
    "    Message Management: To further ensure safety, the bot will delete messages containing dangerous "
    "links after a brief interval, reducing the risk of accidental exposure.\n\n"
    "Purpose:\n"
    "    The integration of SafeLink aims to provide an added layer of protection against phishing, malware, "
    "and other online threats, ensuring a safer environment for all members."
)

# Voting message with bold formatting
vote_message = (
    "**Your opinion matters!**\n"
    "React with 👍 for 'Yes' if you support the bot's implementation for better security.\n\n"
    "React with 👎 for 'No' if you do not wish to have this bot in our server.\n\n"
    "**Please vote and help us make our community safer!**"
)

# Send a poll
send_poll(webhook_url, title, bot_info, vote_message)
