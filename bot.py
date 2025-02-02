# 🔹 الدالة العامة لفحص الروابط
def scan_url(message, direct=False):
    url_to_scan = message.text if direct else message.text.split(" ", 1)[1]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_to_scan}

    # إرسال إشعار ببدء الفحص ومدة الانتظار
    bot.reply_to(message, "🔍 يتم الآن فحص الرابط... ⏳ **سيستغرق الفحص 20 ثانية. الرجاء الانتظار...**")

    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            # انتظار 10 ثوانٍ ثم تحديث المستخدم
            time.sleep(10)
            bot.reply_to(message, "⌛ **ما زال الفحص جاريًا... تبقى 10 ثوانٍ.**")

            # انتظار 10 ثوانٍ إضافية ليصبح المجموع 20 ثانية
            time.sleep(10)

            # جلب النتيجة النهائية
            result_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            result_data = result_response.json()

            if "attributes" in result_data["data"]:
                positives = result_data["data"]["attributes"]["stats"]["malicious"]

                if positives == 0:
                    status = "✅ **الرابط آمن تمامًا بإذن الله، بس خلك حريص! فضاء الإنترنت لا يوجد به أمان.**"
                elif positives <= 3:
                    status = "❌ **الرابط مشبوه، يرجى توخي الحذر.**"
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
