import os
import telebot
import requests
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

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

# ✅ الكلمات المفتاحية للرسالة الترحيبية
GREETING_KEYWORDS = ["السلام عليكم", "السلام", "هلا", "الو", "hello", "hi", "مرحبا", "مرحبا بك"]

# ✅ الرسالة الترحيبية
def get_welcome_message():
    return (
        "👋 مرحبًا بك، أنا *HADI*!\n"
        "🔍 فحص الروابط عبر *VirusTotal!*\n\n"
        "🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.\n"
        "🛡️ أرسل لي أي رابط مشبوه وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.\n\n"
        "📌 *الاستخدام:*\n"
        "1️⃣ أرسل رابطًا مباشرًا، أو استخدم الأمر `/scan <الرابط>`.\n"
        "2️⃣ انتظر قليلاً وسأخبرك بالنتيجة. 🧐\n\n"
        "🤲 *لا تنسوني من دعائكم!*"
    )

# ✅ إنشاء لوحة الأزرار عند النتيجة فقط
def get_result_buttons():
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🔄 فحص رابط آخر", callback_data="rescan"))
    markup.add(InlineKeyboardButton("👤 من أنا؟", callback_data="about"))
    return markup

@bot.message_handler(commands=['start'])
@bot.message_handler(func=lambda message: message.text.lower() in GREETING_KEYWORDS)
def start(message):
    bot.send_message(
        message.chat.id,
        get_welcome_message(),
        parse_mode="Markdown"
    )

@bot.message_handler(commands=['scan'])
@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text.split(" ")[-1]  # دعم الأمر /scan <الرابط>
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        result = response.json()

        if "data" in result and "id" in result["data"]:
            scan_id = result["data"]["id"]
            bot.send_message(
                message.chat.id,
                f"🔄 يتم الآن فحص الرابط... يرجى الانتظار 🔍",
            )

            # إرسال النتيجة مع الأزرار
            bot.send_message(
                message.chat.id,
                f"🔗 [رابط التحليل](https://www.virustotal.com/gui/url/{scan_id})",
                parse_mode="Markdown",
                reply_markup=get_result_buttons()
            )
        else:
            bot.send_message(
                message.chat.id,
                "❌ حدث خطأ أثناء الفحص: لم يتم العثور على 'attributes' في استجابة API.",
                reply_markup=get_result_buttons()
            )

    except Exception as e:
        bot.send_message(
            message.chat.id,
            f"❌ حدث خطأ أثناء الفحص:\n{str(e)}",
            reply_markup=get_result_buttons()
        )

@bot.callback_query_handler(func=lambda call: call.data == "rescan")
def rescan(call):
    bot.send_message(
        call.message.chat.id,
        "📌 أرسل الرابط الذي تريد فحصه مجددًا:"
    )

@bot.callback_query_handler(func=lambda call: call.data == "about")
def about(call):
    bot.send_message(
        call.message.chat.id,
        "👤 *من أنا؟*\n"
        "أنا *HADI*، خبير في اختبار الاختراق والاستجابة للحوادث السيبرانية.\n"
        "📌 قمت بصناعة هذا البوت بسبب كثرة الاحتيال المالي والمعلوماتي.\n"
        "🔍 الأهم من ذلك هو وعيك بخطورة الروابط المشبوهة!\n"
        "💡 قريبًا سأطلق بوت يقوم بفحص الملفات المشبوهة أيضًا.\n\n"
        "🎁 *هذا العمل إهداء لوالديّ وأصدقائي الداعمين لي.*\n"
        "📢 تابعني على منصة X: [HA_cys](https://x.com/HA_cys)",
        parse_mode="Markdown",
        disable_web_page_preview=True
    )

# 🔹 تشغيل البوت
bot.polling()
