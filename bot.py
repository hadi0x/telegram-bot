import os
import time
import requests
import telebot
import re
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ✅ تحميل المتغيرات البيئية
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ✅ التحقق من المتغيرات البيئية
if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية!")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية!")

# 🔹 تهيئة البوت
bot = telebot.TeleBot(TOKEN)
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# 🔹 الكلمات الترحيبية
greetings = ["السلام عليكم", "هلا", "الو", "hello", "hi", "سلام", "مرحبا", "أهلا", "اهلين", "ألو", "/start", "start/"]

# 🔹 التعرف على الروابط
def is_url(text):
    url_pattern = re.compile(r"https?://\S+")
    return bool(url_pattern.search(text))

# 🔹 الرد على التحية
@bot.message_handler(func=lambda message: message.text.lower() in greetings)
def greet_user(message):
    welcome_text = """👋 مرحبًا بك، أنا **HADI**  
🔍 **فحص الروابط عبر VirusTotal**  

🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.  
🛡️ أرسل لي أي رابط مشبوه وسأقوم بفحصه لك.

📌 **الاستخدام**:
1️⃣ **أرسل رابطًا مباشرةً أو استخدم الأمر** `/scan <الرابط>`  
2️⃣ **انتظر قليلاً وسأخبرك بالنتيجة. 😳**  

⚠️ لا تنسوني من دعائكم! 🙌"""

    bot.reply_to(message, welcome_text, parse_mode="Markdown")

# 🔹 فحص الروابط عند إرسالها مباشرة
@bot.message_handler(func=lambda message: is_url(message.text))
def scan_direct_url(message):
    scan_url(message, direct=True)

# 🔹 فحص الروابط عند استخدام الأمر `/scan`
@bot.message_handler(commands=['scan'])
def scan_command_url(message):
    try:
        url_to_scan = message.text.split(" ", 1)[1]
    except IndexError:
        bot.reply_to(message, "❌ **الرجاء إرسال رابط بعد الأمر /scan**")
        return

    scan_url(message, url_to_scan)

# 🔹 الدالة الرئيسية لفحص الروابط
def scan_url(message, direct=False):
    url_to_scan = message.text if direct else message.text.split(" ", 1)[1]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    bot.reply_to(message, "🔍 يتم الآن فحص الرابط... ⏳ **الرجاء الانتظار حتى يتم الحصول على النتيجة.**")

    try:
        # إرسال الرابط إلى VirusTotal
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            # التحقق من النتيجة كل 5 ثوانٍ لمدة 30 ثانية كحد أقصى
            for _ in range(6):  # 6 محاولات * 5 ثواني = 30 ثانية كحد أقصى
                time.sleep(5)
                result_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
                result_data = result_response.json()

                # التحقق مما إذا كانت النتيجة جاهزة
                if "attributes" in result_data["data"] and result_data["data"]["attributes"]["status"] == "completed":
                    positives = result_data["data"]["attributes"]["stats"]["malicious"]

                    if positives == 0:
                        status = "✅ **الرابط آمن تمامًا بإذن الله، لكن كن حذرًا دائمًا.**"
                    elif positives <= 3:
                        status = "⚠️ **الرابط مشبوه، يرجى توخي الحذر.**"
                    else:
                        status = "❌ **الرابط ضار أو احتيالي، لا تقم بفتحه!**"

                    keyboard = InlineKeyboardMarkup()
                    keyboard.add(
                        InlineKeyboardButton("🔄 فحص رابط آخر", callback_data="scan_again"),
                        InlineKeyboardButton("👤 من أنا؟", callback_data="who_am_i")
                    )

                    bot.send_message(message.chat.id, status, reply_markup=keyboard, parse_mode="Markdown")
                    return

            # في حالة عدم توفر النتيجة بعد 30 ثانية
            bot.send_message(message.chat.id, "⏳ **لم يتم الانتهاء من الفحص بعد، حاول مرة أخرى لاحقًا.**")

        else:
            bot.send_message(message.chat.id, "❌ **حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك.**")

    except Exception as e:
        bot.send_message(message.chat.id, f"❌ **حدث خطأ أثناء الفحص:**\n`{str(e)}`", parse_mode="Markdown")

# 🔹 التعامل مع الأزرار التفاعلية
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == "scan_again":
        bot.send_message(call.message.chat.id, "🔍 **أرسل رابطًا جديدًا لفحصه.**")
    elif call.data == "who_am_i":
        about_text = """👤 **أنا HADI**  
💻 **خبير في اختبار الاختراق والاستجابة للحوادث السيبرانية.**  
🛡️ **قمت بصناعة هذا البوت بسبب كثرة الاحتيال المالي والمعلوماتي، والأهم من ذلك هو وعيك!**  
🚀 **قريبًا سأطلق بوت يقوم بفحص الملفات المشبوهة.**  
🎁 **هذا العمل إهداء لوالدي ووالدتي وأصدقائي الداعمين لي.**  

📌 **حسابي على X:** [HA_cys](https://x.com/HA_cys)
"""
        bot.send_message(call.message.chat.id, about_text, parse_mode="Markdown")

# 🔹 تشغيل البوت
bot.polling()
