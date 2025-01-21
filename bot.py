import os
import time
import requests
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ✅ تحميل المتغيرات البيئية
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# ✅ التأكد من أن التوكنات محملة بشكل صحيح
if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

# 🔹 تهيئة البوت
bot = telebot.TeleBot(TOKEN)

# ✅ الكلمات الاستدلالية التي تستدعي الترحيب
GREETINGS = ["السلام عليكم", "السلام", "هلا", "ألو", "Hello", "Hi", "مرحبا", "يا هلا"]

@bot.message_handler(func=lambda message: message.text.strip() in GREETINGS)
def greeting_response(message):
    welcome_text = (
        "👋 مرحبًا بك في **بوت فحص الروابط عبر VirusTotal**!\n"
        "🚀 هذا البوت يساعدك في **اكتشاف الروابط المشبوهة والمواقع الاحتيالية** 🔍\n"
        "🛡 أرسل لي أي **رابط مشبوه** وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.\n\n"
        "📌 **الاستخدام:**\n"
        "• أرسل رابطًا مباشرة أو استخدم الأمر `/scan <الرابط>`.\n\n"
        "📢 **حسابي على X:** [HA_cys](https://x.com/HA_cys)\n"
        "🤲 **لا تنسوني من دعائكم**"
    )
    bot.reply_to(message, welcome_text, parse_mode="Markdown", disable_web_page_preview=True)

@bot.message_handler(commands=['scan'])
def scan_command(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "❌ **الاستخدام الصحيح:** `/scan <الرابط>`", parse_mode="Markdown")
        return
    scan_url(message, parts[1])

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message, url_to_scan=None):
    url_to_scan = url_to_scan or message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            # ⏳ الانتظار 10 ثوانٍ للحصول على نتائج دقيقة
            time.sleep(10)

            # 🔍 جلب نتائج الفحص
            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            report_response = requests.get(report_url, headers=headers)
            report_data = report_response.json()

            if "attributes" not in report_data["data"]:
                bot.reply_to(message, f"❌ حدث خطأ أثناء جلب نتائج التحليل.\n📌 الرد: {report_data}")
                return

            positives = report_data["data"]["attributes"]["stats"]["malicious"]
            total_scans = sum(report_data["data"]["attributes"]["stats"].values())

            # 🟢 تحديد مستوى الخطر
            if positives == 0:
                status = "✅ الرابط آمن تمامًا."
                emoji = "🟢"
            elif positives <= 3:
                status = "⚠️ الرابط **مشبوه**، يرجى توخي الحذر!"
                emoji = "🟠"
            else:
                status = "❌ **الرابط خطير جدًا! لا تقم بفتحه!** 🚨"
                emoji = "🔴"

            # 🖱 أزرار التفاعل
            markup = InlineKeyboardMarkup()
            btn_scan_another = InlineKeyboardButton("🔍 فحص رابط آخر", callback_data="scan_again")
            btn_about = InlineKeyboardButton("🙋‍♂️ من أنا؟", callback_data="about_me")
            markup.add(btn_scan_another, btn_about)

            response_text = (
                f"{emoji} {status}\n"
                f"🔍 **عدد الفحوصات:** {total_scans}\n"
                f"☠️ **تم اكتشافه كخطر من:** {positives} برامج مكافحة الفيروسات\n"
                f"📢 **حسابي على X:** [HA_cys](https://x.com/HA_cys)\n"
                "🤲 **لا تنسوني من دعائكم**"
            )

            bot.send_message(message.chat.id, response_text, reply_markup=markup, parse_mode="Markdown", disable_web_page_preview=True)
        else:
            bot.reply_to(message, "❌ حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك.")

    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# ✅ التعامل مع الأزرار
@bot.callback_query_handler(func=lambda call: call.data == "scan_again")
def scan_again_callback(call):
    bot.send_message(call.message.chat.id, "🔍 **أرسل الرابط الجديد لفحصه.**", parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "about_me")
def about_me_callback(call):
    about_text = (
        "🙋‍♂️ **من أنا؟**\n"
        "👨‍💻 **اسمي HadI، خبير في اختبار الاختراق والاستجابة للحوادث السيبرانية** 🔥\n\n"
        "🛡 **لماذا صنعت هذا البوت؟**\n"
        "📌 بسبب **كثرة الاحتيال المالي والمعلوماتي**، قررت إطلاق بوت يساعد المستخدمين في كشف الروابط المشبوهة بسهولة.\n\n"
        "🚀 **ما القادم؟**\n"
        "قريبًا سأطلق **بوت يقوم بفحص الملفات المشبوهة** 🛠\n\n"
        "🎁 **هذا العمل إهداء لوالدي، والدتي، وأصدقائي الداعمين لي.** 💙\n\n"
        "📢 **حسابي على X:** [HA_cys](https://x.com/HA_cys)"
    )
    bot.send_message(call.message.chat.id, about_text, parse_mode="Markdown", disable_web_page_preview=True)

# 🔹 تشغيل البوت
bot.polling()
