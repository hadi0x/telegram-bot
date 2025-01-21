import os
import telebot
import requests

# ✅ طباعة جميع المتغيرات البيئية للتحقق مما يتم تحميله
print("🔍 جميع المتغيرات البيئية:")
print(os.environ)

# ✅ طباعة المتغيرات البيئية المطلوبة
print("🔍 TELEGRAM_BOT_TOKEN:", os.getenv("TELEGRAM_BOT_TOKEN"))
print("🔍 VIRUSTOTAL_API_KEY:", os.getenv("VIRUSTOTAL_API_KEY"))

# ✅ تحميل المتغيرات البيئية بشكل صحيح
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ✅ التأكد من أن التوكنات محملة بشكل صحيح
if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

# 🔹 تهيئة البوت
bot = telebot.TeleBot(TOKEN)
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message, "✅ مرحبًا بك! أرسل لي رابطًا وسأقوم بفحصه عبر VirusTotal 🔍")

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    try:
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

    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# 🔹 تشغيل البوت
bot.polling()
