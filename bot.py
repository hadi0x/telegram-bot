import os
import requests
import telebot

# ✅ طباعة جميع المتغيرات البيئية للتحقق مما يتم تحميله
print("🔍 جميع المتغيرات البيئية:")
print(os.environ)

# ✅ تحميل المتغيرات البيئية بشكل صحيح
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

# ✅ أوامر البوت
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
        response_json = response.json()  # تحويل الرد إلى JSON

        print("🔍 استجابة API الكاملة:", response_json)  # ✅ طباعة الاستجابة لرؤية المشكلة

        if response.status_code == 200 and "data" in response_json:
            scan_id = response_json["data"]["id"]
            if "attributes" in response_json["data"]:
                positives = response_json["data"]["attributes"]["last_analysis_stats"]["malicious"]

                if positives == 0:
                    status = "✅ الرابط آمن تمامًا."
                elif positives <= 3:
                    status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
                else:
                    status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"

                bot.reply_to(message, f"{status}\n🔗 [رابط التحليل](https://www.virustotal.com/gui/url/{scan_id})")
            else:
                bot.reply_to(message, "❌ حدث خطأ أثناء الفحص: الاستجابة لا تحتوي على 'attributes'.")
        else:
            bot.reply_to(message, f"❌ خطأ في الاستجابة من API: {response_json.get('error', 'مشكلة غير معروفة')}")

    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# 🔹 تشغيل البوت
print("🚀 البوت يعمل الآن...")
bot.polling()
