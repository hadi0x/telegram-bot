import time
import telebot
import requests
import os

# ✅ تحميل المتغيرات البيئية
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

# 🔹 كلمات ترحيبية
@bot.message_handler(func=lambda message: message.text.lower() in ["السلام", "السلام عليكم", "هلا", "hello", "start", "/start", "alo", "الو"])
def welcome_message(message):
    bot.reply_to(message, 
    "👋 مرحبًا بك، أنا HADI فحص الروابط عبر 🔍 VirusTotal!\n\n"
    "🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.\n\n"
    "🛡 أرسل لي أي رابط مشبوه وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.\n\n"
    "📌 الاستخدام:\n"
    "1️⃣ أرسل رابطًا مباشرًا.\n"
    "2️⃣ انتظر قليلًا وسأخبرك بالنتيجة. 😲\n\n"
    "⚠️ لا تنسوني من دعاكم! 🙌"
    )

# 🔹 فحص الروابط
@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    try:
        bot.reply_to(message, "🔍 يتم الآن فحص الرابط... يرجى الانتظار ⏳")
        time.sleep(15)  # إضافة تأخير 15 ثانية لإجراء الفحص

        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            positives = result["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if positives == 0:
                status = "✅ الرابط آمن تمامًا. باذن الله، لكن خلك حريص! فضاء الإنترنت لا يوجد به أمان."
            elif positives <= 3:
                status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
            else:
                status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"

            bot.reply_to(message, status)
        else:
            bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{response.json().get('error', 'لا توجد تفاصيل متاحة')}")

    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# 🔹 تشغيل البوت
bot.polling()
