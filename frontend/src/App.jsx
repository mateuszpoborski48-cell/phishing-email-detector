
import { useState } from "react";
import "./App.css";

function App() {
  const [email, setEmail] = useState("");
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");

  
async function handleScan(event) {
  event.preventDefault();

  if (!email.trim() && !file) {
    setMessage("Please enter an email or upload a file.");
    return;
  }

  setMessage("Sending email for analysis...");

  const formData = new FormData();

  if (file) {
    formData.append("email_file", file);
  } else {
    formData.append("email_text", email);
  }

  try {
    const response = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      body: formData,
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(
        typeof result.detail === "string"
          ? result.detail
          : "Unable to process email."
      );
    }

    setMessage(
      `Email received successfully!
      Subject: ${result.subject}
      Sender: ${result.sender}
      ${result.message}`
    );

  } catch (error) {
    setMessage(`Error: ${error.message}`);
  }
}


  return (
    <div className="app">
      <header className="header">
        <h2>🛡️ Phishing Email Detector</h2>
        <span>Cybersecurity Analysis Tool</span>
      </header>

      <main className="main">
        <h1>Scan an Email for Phishing</h1>
        <p>
          Paste a suspicious email or upload an .eml file
          to begin the analysis.
        </p>

        <form className="scanner" onSubmit={handleScan}>
          <label htmlFor="email">Email Content</label>
          <textarea
            id="email"
            placeholder="Paste the email message here..."
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            rows={9}
          />

          <label htmlFor="emailFile">
            Or Upload an Email (.eml)
          </label>
          <input
            id="emailFile"
            type="file"
            accept=".eml"
            onChange={(e) => {
              setFile(e.target.files[0] || null);
            }}
          />

          <button type="submit">Scan Email</button>

          {message && (
            <div className="result" role="status">
              {message}
            </div>
          )}
        </form>
      </main>
    </div>
  );
}

export default App;
