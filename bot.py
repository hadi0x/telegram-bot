import os
import time
import requests
import telebot
from telebot.types import ReplyKeyboardMarkup, KeyboardButton

# تحميل المتغيرات البيئية
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# التحقق من تحميل المتغيرات البيئية وعرضها في الـ Logs
print("🔍 TELEGRAM_BOT_TOKEN:", TOKEN)
print("🔍 VIRUSTOTAL_API_KEY:", VIRUSTOTAL_API_KEY)

if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

# تهيئة البوت
bot = telebot.TeleBot(TOKEN)

# الكلمات الترحيبية
WELCOME_MESSAGES = ["السلام عليكم", "هلا", "أهلاً", "مرحباً", "الو", "hello", "/start", "start/"]

@bot.message_handler(func=lambda message: message.text.lower() in WELCOME_MESSAGES)
def welcome_message(message):
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🔄 فحص رابط آخر"))
    markup.add(KeyboardButton("ℹ️ من أنا؟"))
    
    bot.reply_to(message, """
👋 مرحبًا بك، أنا HADI!
🔍 فحص الروابط عبر **VirusTotal**

🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.
🛡️ أرسل لي أي رابط مشبوه وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.

📌 **الاستخدام:**
1️⃣ أرسل رابطًا مباشرةً أو استخدم الأمر.
2️⃣ انتظر قليلاً وسأخبرك بالنتيجة. 😨

⚠️ لا تنسوني من دعاكم!
    ", parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    bot.reply_to(message, "🔍 يتم الآن فحص الرابط... يرجى الانتظار ⏳")
    time.sleep(15)  # تأخير لمدة 15 ثانية لمحاكاة وقت الفحص

    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]
            analysis_url = f"https://www.virustotal.com/gui/url/{scan_id}"
            
            report_response = requests.get(f"{VIRUSTOTAL_URL}/{scan_id}", headers=headers)
            report_result = report_response.json()
            
            positives = report_result["data"]["attributes"]["last_analysis_stats"]["malicious"]
            
            if positives == 0:
                status = "✅ الرابط آمن تمامًا. باذن الله، لكن خلك حريص، فضاء الإنترنت لا يوجد به أمان!"
            elif positives <= 3:
                status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
            else:
                status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"
            
            markup = ReplyKeyboardMarkup(resize_keyboard=True)
            markup.add(KeyboardButton("🔄 فحص رابط آخر"))
            markup.add(KeyboardButton("ℹ️ من أنا؟"))
            
            bot.reply_to(message, status, reply_markup=markup)
        else:
            bot.reply_to(message, "❌ حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك.")
    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص: {str(e)}")

@bot.message_handler(func=lambda message: message.text == "ℹ️ من أنا؟")
def about_me(message):
    bot.reply_to(message, """
👤 **HADI**

🔍 **خبير في اختبار الاختراق والاستجابة للحوادث السيبرانية**
🚀 قمت بصناعة هذا البوت بسبب كثرة الاحتيال المالي والمعلوماتي، والأهم من ذلك هو وعيك!
🛡️ قريبًا سأطلق بوت يقوم بفحص الملفات المشبوهة.
🎁 هذا العمل إهداء لوالديّ وأصدقائي الداعمين لي.
📌 تابعني على منصة X: @HA_cys
    """, parse_mode="Markdown")

# تشغيل البوت
bot.polling()
