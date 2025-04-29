import requests
import vonage

def send_sms (to, otp):
    try:
        client = vonage.Client(key="e71d7746", secret="1jFrUajQQQ8DanNX")
        sms = vonage.Sms(client)
        body = {
                "from": "VeriOne",
                "to": to,
                "text": f"Your OTP for VeriOne is: {otp}, valid for 5 minutes.",
            }
        
        print(body)

        responseData = sms.send_message(
            body
        )

        if responseData["messages"][0]["status"] == "0":
            print("Message sent successfully.")
        else:
            raise ValueError("Nexmo returned an error: %s" % responseData["messages"][0]["error-text"])
    except Exception as e:
        raise(e)