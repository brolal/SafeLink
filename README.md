# SafeLink Discord Bot

## Overview
SafeLink is a Discord bot designed to enhance security and moderation in Discord servers. It scans messages for potentially harmful links using the VirusTotal API and alerts moderators about any suspicious activity. SafeLink can detect shortened URLs and analyze domains for known security threats, making it an essential tool for maintaining a safe online community.

## Features
- **Link Detection:** Scans all messages for URLs and identifies shortened links.
- **VirusTotal Integration:** Analyzes URLs for malicious content using the VirusTotal API.
- **Moderator Alerts:** Notifies moderators of detected threats and suspicious links.
- **Automatic Message Handling:** Deletes messages containing harmful links and sends warnings.

## Installation
To set up SafeLink on your server, follow these steps:

### Prerequisites
- Python 3.8 or higher.
- A Discord account and a server where you have administrative privileges.
- A VirusTotal API key (obtainable from [VirusTotal](https://www.virustotal.com/)).

### Steps
1. **Clone the Repository:**
   ```
   git clone https://github.com/brolal/SafeLink
   cd safelink
   ```

2. **Install Dependencies:**
   ```
   pip install -r requirements.txt
   ```

3. **Set Environment Variables:**
   Create a `.env` file in the root directory and add the following:
   ```
   DISCORD_TOKEN=<your_discord_bot_token>
   VIRUSTOTAL_API_KEY=<your_virustotal_api_key>
   ```

4. **Run the Bot:**
   ```
   python safelink.py
   ```

## Configuration
- **`SPECIFIC_CHANNEL_ID`:** List of channel IDs where the bot is active.
- **`MODERATOR_IDS`:** Discord IDs of the moderators to be alerted.

## Usage
Once the bot is running, it will monitor messages in the specified channels. If it detects a potentially harmful link, it will:
1. Send an alert message to the channel.
2. Notify the moderators.
3. Delete the original message containing the suspicious link.
![image](https://github.com/brolal/SafeLink/assets/82910708/42ae0cf2-f312-4e73-909a-2f4a85f5b76e)

## Bot permissions
![perms](https://github.com/brolal/SafeLink/assets/82910708/069f6a33-cd69-41b7-8d91-eecbe5ca7133)

## Contributing
Contributions, issues, and feature requests are welcome. Feel free to check [issues page](https://github.com/brolal/SafeLink/issues) if you want to contribute.

## License
Distributed under the MIT License. See [MIT](https://github.com/brolal/SafeLink/blob/main/LICENSE) file for more information.

## Acknowledgments
- [Discord.py](https://github.com/Rapptz/discord.py)
- [VirusTotal API](https://www.virustotal.com/)
