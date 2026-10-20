
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from email.message import EmailMessage

from risk_analyser import analyse_full_email

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
        if (
            not email_file.filename
            or not email_file.filename.lower().endswith(".eml")
        ):
            raise HTTPException(
                400, "Only .eml files are allowed"
            )

        raw_email = await email_file.read(MAX_EMAIL_SIZE + 1)

        if len(raw_email) > MAX_EMAIL_SIZE:
            raise HTTPException(
                413, "Email file is too large"
            )

    elif email_text and email_text.strip():
        if len(email_text.encode("utf-8")) > MAX_EMAIL_SIZE:
            raise HTTPException(
                413, "Email text is too large"
            )

        # Wrap pasted text in a basic email message.
        message = EmailMessage()
        message["From"] = "unknown@example.invalid"
        message["Subject"] = "Pasted Email"
        message.set_content(email_text)
        raw_email = message.as_bytes()

    else:
        raise HTTPException(
            400, "Please enter or upload an email"
        )

    try:
        result = analyse_full_email(raw_email)
        return result

    except Exception:
        raise HTTPException(
            400, "Unable to analyse this email"
        )
