import os
import time
import requests
import telebot
import re
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ✅ تحميل المتغيرات البيئية
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ✅ طباعة المتغيرات البيئية للتحقق منها
print("🔍 TELEGRAM_BOT_TOKEN:", TOKEN)
print("🔍 VIRUSTOTAL_API_KEY:", VIRUSTOTAL_API_KEY)

# ✅ التحقق من وجود التوكنات قبل بدء البوت
if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

# 🔹 تهيئة البوت
bot = telebot.TeleBot(TOKEN)
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# 🔹 الكلمات الترحيبية
greetings = ["السلام عليكم", "هلا", "الو", "hello", "hi", "سلام", "مرحبا", "أهلا", "اهلين", "ألو"]

# 🔹 التعرف على الروابط
def is_url(text):
    url_pattern = re.compile(r"https?://\S+")
    return bool(url_pattern.search(text))

@bot.message_handler(func=lambda message: message.text.lower() in greetings)
def greet_user(message):
    welcome_text = """👋 مرحبًا بك، أنا **HADI**  
🔍 **فحص الروابط عبر VirusTotal**  

🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.  
🛡️ أرسل لي أي رابط مشبوه وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.

📌 **الاستخدام**:
1️⃣ **أرسل رابطًا مباشرةً أو استخدم الأمر** `/scan <الرابط>`  
2️⃣ **انتظر قليلاً وسأخبرك بالنتيجة. 😳**  

⚠️ لا تنسوني من دعائكم! 🙌"""
    bot.reply_to(message, welcome_text, parse_mode="Markdown")

# 🔹 فحص الروابط عند إرسالها مباشرةً بدون الحاجة إلى `/scan`
@bot.message_handler(func=lambda message: is_url(message.text))
def scan_direct_url(message):
    scan_url(message, direct=True)

# 🔹 فحص الروابط عند استخدام الأمر `/scan`
@bot.message_handler(commands=['scan'])
def scan_command_url(message):
    try:
        url_to_scan = message.text.split(" ", 1)[1]  # استخراج الرابط من الرسالة
    except IndexError:
        bot.reply_to(message, "❌ **الرجاء إرسال رابط بعد الأمر /scan**")
        return

    scan_url(message, url_to_scan)

# 🔹 الدالة العامة لفحص الروابط
def scan_url(message, direct=False):
    url_to_scan = message.text if direct else message.text.split(" ", 1)[1]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    # إرسال إشعار ببدء الفحص
    bot.reply_to(message, "🔍 يتم الآن فحص الرابط... يرجى الانتظار ⏳")

    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            # انتظار 10 ثواني قبل جلب النتيجة
            time.sleep(10)

            # جلب النتيجة النهائية
            result_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            result_data = result_response.json()

            if "attributes" in result_data["data"]:
                positives = result_data["data"]["attributes"]["stats"]["malicious"]

                if positives == 0:
                    status = "✅ **الرابط آمن تمامًا بإذن الله، بس خلك حريص! فضاء الإنترنت لا يوجد به أمان.**"
                elif positives <= 3:
                    status = "⚠️ **الرابط مشبوه، يرجى توخي الحذر.**"
                else:
                    status = "❌ **الرابط احتيالي أو ضار، لا تقم بفتحه!**"

                # 🔹 إضافة أزرار (فحص رابط آخر، من أنا)
                keyboard = InlineKeyboardMarkup()
                keyboard.row_width = 1
                keyboard.add(
                    InlineKeyboardButton("🔄 فحص رابط آخر", callback_data="scan_again"),
                    InlineKeyboardButton("👤 من أنا؟", callback_data="who_am_i")
                )

                bot.reply_to(message, status, reply_markup=keyboard, parse_mode="Markdown")
            else:
                bot.reply_to(message, "❌ **حدث خطأ أثناء الفحص: لم يتم العثور على 'attributes' في استجابة API.**")
        else:
            bot.reply_to(message, "❌ **حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك.**")

    except Exception as e:
        bot.reply_to(message, f"❌ **حدث خطأ أثناء الفحص:**\n`{str(e)}`", parse_mode="Markdown")

# 🔹 التعامل مع الأزرار
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
