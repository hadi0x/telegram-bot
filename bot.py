import telebot
import requests
import os

TOKEN = os.getenv("7899572276:AAG36D1sII_cvHJauTAVshNreoMSYa1QF7k")
VIRUSTOTAL_API_KEY = os.getenv("7a9df9d88643a593720947c3d81bd56e71dc978cb2204618b89a3d32d3211174")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message, "✅ مرحبًا بك! أرسل لي رابطًا وسأقوم بفحصه عبر VirusTotal 🔍")

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        scan_id = result["data"]["id"]
        positives = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        
        if positives == 0:
            status = "✅ الرابط آمن تمامًا."
        elif positives <= 3:
            status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
        else:
            status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"

        bot.reply_to(message, f"{status}\n🔗 [رابط التحليل](https://www.virustotal.com/gui/url/{scan_id})")
    else:
        bot.reply_to(message, "❌ حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك.")

bot.polling()
