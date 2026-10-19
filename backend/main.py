
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from email import policy
from email.parser import BytesParser

app = FastAPI(title="Phishing Email Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

MAX_EMAIL_SIZE = 2 * 1024 * 1024


@app.get("/")
def home():
    return {
        "message": "Phishing Email Detector API is running"
    }


@app.post("/scan")
async def scan_email(
    email_text: str | None = Form(default=None),
    email_file: UploadFile | None = File(default=None),
):
    if email_file is not None:
        if not email_file.filename or not email_file.filename.lower().endswith(".eml"):
            raise HTTPException(400, "Only .eml files are allowed")

        raw = await email_file.read(MAX_EMAIL_SIZE + 1)

        if len(raw) > MAX_EMAIL_SIZE:
            raise HTTPException(413, "Email file is too large")

        message = BytesParser(policy=policy.default).parsebytes(raw)

        subject = str(message.get("Subject", ""))
        sender = str(message.get("From", ""))

        body_part = message.get_body(preferencelist=("plain",))
        content = body_part.get_content() if body_part else ""

    elif email_text and email_text.strip():
        if len(email_text.encode("utf-8")) > MAX_EMAIL_SIZE:
            raise HTTPException(413, "Email text is too large")

        subject = "Pasted email"
        sender = "Not provided"
        content = email_text

    else:
        raise HTTPException(400, "Please submit an email")

    return {
        "status": "received",
        "subject": subject,
        "sender": sender,
        "preview": content[:300],
        "message": "Email received. Phishing detection coming in Week 2."
    }
