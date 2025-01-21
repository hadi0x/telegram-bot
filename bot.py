import os
import requests
import json
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# ✅ تحميل المتغيرات البيئية من `Railway`
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ✅ التأكد من أن التوكنات محملة بشكل صحيح
if not BOT_TOKEN:
    raise ValueError("❌ خطأ: لم يتم العثور على `TELEGRAM_BOT_TOKEN` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ خطأ: لم يتم العثور على `VIRUSTOTAL_API_KEY` في المتغيرات البيئية! تأكد من إضافته في `Railway`.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """رد ترحيبي عند تشغيل البوت."""
    await update.message.reply_text(
        "✅ مرحبًا بك في بوت فحص الروابط عبر VirusTotal!\n"
        "📌 استخدم `/scan <الرابط>` لفحص الرابط."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إرسال قائمة بالأوامر المتاحة."""
    await update.message.reply_text(
        "📌 الأوامر المتاحة:\n"
        "✅ /start - بدء المحادثة مع البوت\n"
        "✅ /help - عرض قائمة الأوامر\n"
        "✅ /scan <الرابط> - فحص الرابط باستخدام VirusTotal"
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """فحص الروابط باستخدام VirusTotal API."""
    try:
        url = context.args[0]
    except IndexError:
        await update.message.reply_text("❌ الاستخدام الصحيح: `/scan <الرابط>`")
        return

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}
    
    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            # ✅ جلب النتائج التفصيلية
            analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            analysis_result = analysis_response.json()

            positives = analysis_result["data"]["attributes"]["stats"]["malicious"]
            total = sum(analysis_result["data"]["attributes"]["stats"].values())

            if positives == 0:
                status = "✅ الرابط آمن تمامًا."
            elif positives <= 3:
                status = "⚠️ الرابط مشبوه، يرجى توخي الحذر."
            else:
                status = "❌ الرابط احتيالي أو ضار، لا تقم بفتحه!"

            message = (
                f"{status}\n"
                f"🔍 عدد برامج الحماية التي اكتشفت التهديد: {positives}/{total}\n"
                f"🔗 [رابط التحليل](https://www.virustotal.com/gui/url/{scan_id})"
            )
        else:
            message = "❌ حدث خطأ أثناء الفحص، تأكد من مفتاح API الخاص بك."

        await update.message.reply_text(message)

    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ أثناء الفحص:\n{str(e)}")

# ✅ إنشاء التطبيق
app = ApplicationBuilder().token(BOT_TOKEN).build()

# ✅ إضافة الأوامر إلى البوت
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("scan", scan))

# ✅ تشغيل البوت
app.run_polling()
