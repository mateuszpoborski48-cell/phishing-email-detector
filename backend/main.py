
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from risk_analyser import analyse_full_email
from database import (
    save_scan,
    get_scan_history,
    get_scan_statistics,
)

app = FastAPI(title="Phishing Email Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
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
    # 1. Handle uploaded .eml files
    if email_file is not None:
        if (
            not email_file.filename
            or not email_file.filename.lower().endswith(".eml")
        ):
            raise HTTPException(
                status_code=400,
                detail="Only .eml files are allowed",
            )

        raw_email = await email_file.read(MAX_EMAIL_SIZE + 1)

        if len(raw_email) > MAX_EMAIL_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Email file is too large",
            )

        if not raw_email.strip():
            raise HTTPException(
                status_code=400,
                detail="The uploaded email is empty",
            )

    # 2. Handle pasted email text
    elif email_text and email_text.strip():
        if len(email_text.encode("utf-8")) > MAX_EMAIL_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Email text is too large",
            )

        # Pass original text directly to the analyser.
        # This preserves From and Subject headers.
        raw_email = email_text

    else:
        raise HTTPException(
            status_code=400,
            detail="Please enter or upload an email",
        )

    # 3. Analyse email
    try:
        result = analyse_full_email(raw_email)

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to analyse this email",
        )

    # 4. Save results to database
    try:
        scan_id = save_scan(result)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Scan completed but could not be saved",
        )

    result["scan_id"] = scan_id

    return result


@app.get("/history")
def history():
    return get_scan_history()


@app.get("/statistics")
def statistics():
    return get_scan_statistics()
