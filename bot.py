import telebot
import requests
import os
import time
from telebot.types import ReplyKeyboardMarkup, KeyboardButton

# 🔹 تحميل المتغيرات البيئية
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# ✅ التحقق من تحميل المتغيرات البيئية وعرضها في الـ Logs
print("🔍 TELEGRAM_BOT_TOKEN:", TOKEN)
print("🔍 VIRUSTOTAL_API_KEY:", VIRUSTOTAL_API_KEY)

# ✅ التأكد من أن التوكنات محملة بشكل صحيح
if not TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

# 🔹 تهيئة البوت
bot = telebot.TeleBot(TOKEN)

# 📌 الكلمات الترحيبية التي تشغل البوت
START_KEYWORDS = ["السلام عليكم", "السلام", "هلا", "الو", "hello", "hi", "/start", "start"]

# 🔹 إنشاء لوحة مفاتيح للأزرار
def main_keyboard():
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🔄 فحص رابط آخر"))
    markup.add(KeyboardButton("👤 من أنا؟"))
    return markup

# 🔹 استقبال الرسائل الترحيبية
@bot.message_handler(func=lambda message: message.text.lower() in START_KEYWORDS)
def welcome_message(message):
    welcome_text = (
        "👋 مرحبًا بك، أنا HADI!\n"
        "🔍 **فحص الروابط عبر VirusTotal**\n\n"
        "🚀 سيساعدك هذا البوت في اكتشاف الروابط المشبوهة والمواقع الاحتيالية.\n"
        "🛡️ أرسل لي أي رابط مشبوه وسأقوم بفحصه لك باستخدام قاعدة بيانات عالمية لمكافحة الاحتيال.\n\n"
        "📌 **الاستخدام:**\n"
        "1️⃣ أرسل رابطًا مباشرةً.\n"
        "2️⃣ انتظر قليلًا وسأخبرك بالنتيجة. 😲\n\n"
        "⚠️ **لا تنسَ توخي الحذر عند التعامل مع الروابط غير الموثوقة!**"
    )
    bot.reply_to(message, welcome_text, reply_markup=main_keyboard())

# 🔍 فحص الروابط
@bot.message_handler(func=lambda message: message.text.startswith("http"))
def scan_url(message):
    url_to_scan = message.text
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    try:
        bot.reply_to(message, f"🔍 يتم الآن فحص الرابط... ⏳ يرجى الانتظار")
        time.sleep(15)  # ⏳ انتظار 15 ثانية لإتاحة وقت للفحص

        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()

            # ✅ التأكد من أن البيانات تحتوي على attributes قبل محاولة الوصول إليها
            if "data" in result and "attributes" in result["data"]:
                positives = result["data"]["attributes"]["last_analysis_stats"]["malicious"]

                if positives == 0:
                    status = "✅ الرابط آمن تمامًا. باذن الله، لكن خلك حريص! فضاء الإنترنت لا يوجد به أمان."
                elif positives <= 3:
                    status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
                else:
                    status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"

                bot.reply_to(message, status, reply_markup=main_keyboard())

            else:
                bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص: لم يتم العثور على 'attributes' في استجابة API.\n📌 الرد: {result}")

        else:
            bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص: {response.json().get('error', 'لا توجد تفاصيل متاحة')}")

    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# 👤 "من أنا" - معلومات حول البوت
@bot.message_handler(func=lambda message: message.text == "👤 من أنا؟")
def about_me(message):
    about_text = (
        "👤 **HADI**\n"
        "🛡️ خبير في **اختبار الاختراق والاستجابة للحوادث السيبرانية**.\n"
        "💡 قمت بصناعة هذا البوت بسبب **كثرة الاحتيال المالي والمعلوماتي**.\n"
        "🔍 الأهم من ذلك هو **وعيك وحذرك من الروابط المشبوهة**!\n\n"
        "🚀 قريبًا، سأطلق بوت يقوم بفحص الملفات المشبوهة أيضًا!\n\n"
        "🎁 هذا العمل إهداء **لوالدي ووالدتي وأصدقائي الداعمين لي**. 💙\n\n"
        "📌 تابعني على **X (تويتر)**: [HA_cys](https://x.com/HA_cys)"
    )
    bot.reply_to(message, about_text, disable_web_page_preview=True, reply_markup=main_keyboard())

# 🔹 تشغيل البوت
bot.polling()
