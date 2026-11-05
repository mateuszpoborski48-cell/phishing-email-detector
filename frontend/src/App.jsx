
import { useState, useEffect, useCallback } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [activeTab, setActiveTab] = useState("scan");
  const [email, setEmail] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [statistics, setStatistics] = useState(null);
  const [history, setHistory] = useState([]);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState("");

  const loadDashboard = useCallback(async () => {
    setDashboardLoading(true);
    setDashboardError("");

    try {
      const [statsResponse, historyResponse] = await Promise.all([
        fetch(`${API_URL}/statistics`),
        fetch(`${API_URL}/history`),
      ]);

      if (!statsResponse.ok || !historyResponse.ok) {
        throw new Error("Unable to retrieve dashboard data.");
      }

      const statsData = await statsResponse.json();
      const historyData = await historyResponse.json();

      setStatistics(statsData);
      setHistory(historyData);
    } catch (err) {
      setDashboardError(err.message || "Dashboard unavailable.");
    } finally {
      setDashboardLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "dashboard") {
      loadDashboard();
    }
  }, [activeTab, loadDashboard]);

  async function handleScan(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!email.trim() && !file) {
      setError("Please paste an email or upload an .eml file.");
      return;
    }

    setLoading(true);

    try {
      const formData = new FormData();

      if (file) {
        formData.append("email_file", file);
      } else {
        formData.append("email_text", email);
      }

      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let message = `Scan failed (${response.status})`;

        try {
          const data = await response.json();
          if (typeof data.detail === "string") {
            message = data.detail;
          }
        } catch {
          // Keep default message
        }

        throw new Error(message);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(
        err instanceof TypeError
          ? "Cannot connect to FastAPI. Check port 8000."
          : err.message || "An unexpected error occurred."
      );
    } finally {
      setLoading(false);
    }
  }

  function getRiskColor(level) {
    switch (level?.toLowerCase()) {
      case "high":
        return "#ef4444";
      case "medium":
        return "#f59e0b";
      case "low":
        return "#22c55e";
      default:
        return "#94a3b8";
    }
  }

  function formatDate(dateString) {
    if (!dateString) return "Unknown";

    const date = new Date(dateString);
    return Number.isNaN(date.getTime())
      ? "Unknown"
      : date.toLocaleString();
  }

  const total = statistics?.total_scans || 0;
  const high = statistics?.high_risk || 0;
  const medium = statistics?.medium_risk || 0;
  const low = statistics?.low_risk || 0;

  return (
    <div className="app-container">
      <header className="header">
        <h1>🛡️ Phishing Email Detector</h1>
        <p>Cybersecurity Analysis Tool</p>
      </header>

      <nav className="navigation">
        <button
          className={activeTab === "scan" ? "active" : ""}
          onClick={() => setActiveTab("scan")}
        >
          Scan Email
        </button>

        <button
          className={activeTab === "dashboard" ? "active" : ""}
          onClick={() => setActiveTab("dashboard")}
        >
          Dashboard
        </button>
      </nav>

      <main className="main-content">
        {activeTab === "scan" && (
          <>
            <h2>Scan an Email for Phishing</h2>
            <p className="description">
              Paste a suspicious email or upload an .eml file.
            </p>

            <form onSubmit={handleScan} className="scan-form">
              <label htmlFor="email-content">Email Content</label>

              <textarea
                id="email-content"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Paste the email message here..."
                rows={10}
                disabled={loading}
              />

              <label htmlFor="email-file">
                Or Upload an Email (.eml)
              </label>

              <input
                id="email-file"
                type="file"
                accept=".eml,message/rfc822"
                disabled={loading}
                onChange={(e) =>
                  setFile(e.target.files?.[0] || null)
                }
              />

              {file && (
                <div className="file-info">
                  Selected: {file.name}
                  <button
                    type="button"
                    onClick={() => {
                      setFile(null);
                      document.getElementById("email-file").value = "";
                    }}
                  >
                    Remove
                  </button>
                </div>
              )}

              <button
                type="submit"
                className="scan-button"
                disabled={loading}
              >
                {loading ? "Scanning..." : "Scan Email"}
              </button>
            </form>

            {error && (
              <div className="error-box" role="alert">
                Error: {error}
              </div>
            )}

            {result && (
              <section className="results-card">
                <h3>Scan Results</h3>

                <div className="result-row">
                  <strong>Risk Level:</strong>
                  <span
                    style={{
                      color: getRiskColor(result.risk_level),
                    }}
                  >
                    {result.risk_level || "Unknown"}
                  </span>
                </div>

                <div className="result-row">
                  <strong>Risk Score:</strong>
                  <span>{result.risk_score ?? 0}/100</span>
                </div>

                <div className="risk-bar">
                  <div
                    className="risk-fill"
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(0, Number(result.risk_score) || 0)
                      )}%`,
                      backgroundColor: getRiskColor(
                        result.risk_level
                      ),
                    }}
                  />
                </div>

                <div className="result-row">
                  <strong>Subject:</strong>
                  <span>{result.subject || "Not provided"}</span>
                </div>

                <div className="result-row">
                  <strong>Sender:</strong>
                  <span>
                    {result.sender === "unknown@example.invalid"
                      ? "Not available (pasted email)"
                      : result.sender || "Not provided"}
                  </span>
                </div>

                <h4>Detected Warnings</h4>

                {result.warnings?.length ? (
                  <ul className="warnings-list">
                    {result.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No phishing indicators detected.</p>
                )}

                {result.scan_id != null && (
                  <p className="scan-id">
                    Saved to database — Scan ID: {result.scan_id}
                  </p>
                )}
              </section>
            )}
          </>
        )}

        {activeTab === "dashboard" && (
          <section className="dashboard">
            <div className="dashboard-heading">
              <div>
                <h2>Security Dashboard</h2>
                <p className="description">
                  Phishing scan statistics and history
                </p>
              </div>

              <button
                className="refresh-button"
                onClick={loadDashboard}
                disabled={dashboardLoading}
              >
                {dashboardLoading ? "Loading..." : "Refresh"}
              </button>
            </div>

            {dashboardError && (
              <div className="error-box">
                {dashboardError}
              </div>
            )}

            {statistics && (
              <>
                <div className="stats-grid">
                  <div className="stat-card">
                    <span>Total Scans</span>
                    <strong>{total}</strong>
                  </div>

                  <div className="stat-card">
                    <span>Average Risk</span>
                    <strong>
                      {Number(
                        statistics.average_risk || 0
                      ).toFixed(1)}
                      /100
                    </strong>
                  </div>

                  <div className="stat-card">
                    <span>High Risk</span>
                    <strong className="high-text">{high}</strong>
                  </div>

                  <div className="stat-card">
                    <span>Low Risk</span>
                    <strong className="low-text">{low}</strong>
                  </div>
                </div>

                <div className="dashboard-panel">
                  <h3>Risk Distribution</h3>

                  {total > 0 ? (
                    <>
                      <div className="distribution-bar">
                        <div
                          className="distribution-high"
                          style={{ width: `${high / total * 100}%` }}
                        />
                        <div
                          className="distribution-medium"
                          style={{ width: `${medium / total * 100}%` }}
                        />
                        <div
                          className="distribution-low"
                          style={{ width: `${low / total * 100}%` }}
                        />
                      </div>

                      <div className="distribution-legend">
                        <span className="high-text">
                          High: {high}
                        </span>
                        <span className="medium-text">
                          Medium: {medium}
                        </span>
                        <span className="low-text">
                          Low: {low}
                        </span>
                      </div>
                    </>
                  ) : (
                    <p>No scans recorded yet.</p>
                  )}
                </div>
              </>
            )}

            <div className="dashboard-panel">
              <h3>Recent Scan History</h3>

              {history.length === 0 ? (
                <p>No scan history available.</p>
              ) : (
                <div className="table-wrapper">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Scan ID</th>
                        <th>Date</th>
                        <th>Score</th>
                        <th>Risk</th>
                        <th>Warnings</th>
                      </tr>
                    </thead>

                    <tbody>
                      {history.map((scan) => (
                        <tr key={scan.id}>
                          <td>#{scan.id}</td>
                          <td>{formatDate(scan.scan_date)}</td>
                          <td>{scan.risk_score}/100</td>
                          <td>
                            <span
                              className="risk-badge"
                              style={{
                                color: getRiskColor(scan.risk_level),
                                borderColor: getRiskColor(scan.risk_level),
                              }}
                            >
                              {scan.risk_level}
                            </span>
                          </td>
                          <td>
                            {scan.warning_count ?? 0}
                            {scan.warnings?.length > 0 && (
                              <details>
                                <summary>View warnings</summary>
                                <ul>
                                  {scan.warnings.map((warning, index) => (
                                    <li key={index}>{warning}</li>
                                  ))}
                                </ul>
                              </details>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        Phishing Email Detector — Cybersecurity Project
      </footer>
    </div>
  );
}

export default App;
