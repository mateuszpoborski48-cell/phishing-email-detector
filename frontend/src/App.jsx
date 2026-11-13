
import { useState, useEffect, useCallback } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

// Risk level colours
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

// Format database dates
function formatDate(dateString) {
  if (!dateString) return "Unknown";

  const date = new Date(dateString);

  return Number.isNaN(date.getTime())
    ? "Unknown"
    : date.toLocaleString();
}

// Reusable risk badge
function RiskBadge({ level }) {
  return (
    <span
      className="risk-badge"
      style={{
        color: getRiskColor(level),
        borderColor: getRiskColor(level),
      }}
    >
      {level || "Unknown"}
    </span>
  );
}

// Reusable phishing explanation section
function PhishingExplanations({ scan }) {
  if (!scan) return null;

  return (
    <>
      {scan.warning_details?.length > 0 && (
        <div className="explanations-section">
          <h4>Why Is This Email Suspicious?</h4>

          {scan.warning_details.map((detail, index) => (
            <div className="explanation-card" key={index}>
              <h5>{detail.warning}</h5>

              <p>
                <strong>Explanation:</strong>{" "}
                {detail.explanation}
              </p>

              <p>
                <strong>Recommendation:</strong>{" "}
                {detail.recommendation}
              </p>
            </div>
          ))}
        </div>
      )}

      {scan.overall_recommendation && (
        <div
          className="recommendation-panel"
          style={{
            borderColor: getRiskColor(scan.risk_level),
          }}
        >
          <h4>{scan.overall_recommendation.title}</h4>

          <p>{scan.overall_recommendation.message}</p>
        </div>
      )}
    </>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState("scan");

  // Email scanner
  const [email, setEmail] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Dashboard and database
  const [statistics, setStatistics] = useState(null);
  const [history, setHistory] = useState([]);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState("");

  // Database Explorer controls
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("All");
  const [sortOrder, setSortOrder] = useState("newest");
  const [selectedScan, setSelectedScan] = useState(null);

  // Load dashboard and database records
  const loadDashboard = useCallback(async () => {
    setDashboardLoading(true);
    setDashboardError("");

    try {
      const [statsResponse, historyResponse] = await Promise.all([
        fetch(`${API_URL}/statistics`),
        fetch(`${API_URL}/history`),
      ]);

      if (!statsResponse.ok || !historyResponse.ok) {
        throw new Error(
          "Unable to retrieve database information."
        );
      }

      const statsData = await statsResponse.json();
      const historyData = await historyResponse.json();

      if (!Array.isArray(historyData)) {
        throw new Error("Invalid database history response.");
      }

      setStatistics(statsData);
      setHistory(historyData);
    } catch (err) {
      setDashboardError(
        err instanceof TypeError
          ? "Cannot connect to FastAPI. Check port 8000."
          : err.message || "Database unavailable."
      );
    } finally {
      setDashboardLoading(false);
    }
  }, []);


useEffect(() => {
  if (
    activeTab !== "dashboard" &&
    activeTab !== "database"
  ) {
    return;
  }

  const timeoutId = setTimeout(() => {
    void loadDashboard();
  }, 0);

  return () => clearTimeout(timeoutId);
}, [activeTab, loadDashboard]);


  // Scan an email
  async function handleScan(event) {
    event.preventDefault();

    setError("");
    setResult(null);

    if (!email.trim() && !file) {
      setError(
        "Please paste an email or upload an .eml file."
      );
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
          // Keep the default error message
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

  // Filter and sort saved scans
  const filteredHistory = history
    .filter((scan) => {
      const query = search.trim().toLowerCase();

      const searchableText = [
        scan.id,
        scan.risk_score,
        scan.risk_level,
        scan.scan_date,
        ...(Array.isArray(scan.warnings)
          ? scan.warnings
          : []),
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        query === "" || searchableText.includes(query);

      const matchesRisk =
        riskFilter === "All" ||
        scan.risk_level?.toLowerCase() ===
          riskFilter.toLowerCase();

      return matchesSearch && matchesRisk;
    })
    .sort((a, b) => {
      if (sortOrder === "oldest") {
        return (
          new Date(a.scan_date) -
          new Date(b.scan_date)
        );
      }

      if (sortOrder === "highest") {
        return (
          Number(b.risk_score) -
          Number(a.risk_score)
        );
      }

      if (sortOrder === "lowest") {
        return (
          Number(a.risk_score) -
          Number(b.risk_score)
        );
      }

      return (
        new Date(b.scan_date) -
        new Date(a.scan_date)
      );
    });

  const total = statistics?.total_scans || 0;
  const high = statistics?.high_risk || 0;
  const medium = statistics?.medium_risk || 0;
  const low = statistics?.low_risk || 0;

  return (
    <div className="app-container">

      {/* HEADER */}

      <header className="header">
        <h1>🛡️ Phishing Email Detector</h1>
        <p>Cybersecurity Analysis Tool</p>
      </header>

      {/* NAVIGATION */}

      <nav className="navigation">
        <button
          className={
            activeTab === "scan" ? "active" : ""
          }
          onClick={() => setActiveTab("scan")}
        >
          Scan Email
        </button>

        <button
          className={
            activeTab === "dashboard" ? "active" : ""
          }
          onClick={() => setActiveTab("dashboard")}
        >
          Dashboard
        </button>

        <button
          className={
            activeTab === "database" ? "active" : ""
          }
          onClick={() => setActiveTab("database")}
        >
          Database Explorer
        </button>
      </nav>

      <main className="main-content">

        {/* ===================================
            PAGE 1 - EMAIL SCANNER
           =================================== */}

        {activeTab === "scan" && (
          <>
            <h2>Scan an Email for Phishing</h2>

            <p className="description">
              Paste a suspicious email or upload an .eml file.
            </p>

            <form
              onSubmit={handleScan}
              className="scan-form"
            >
              <label htmlFor="email-content">
                Email Content
              </label>

              <textarea
                id="email-content"
                value={email}
                onChange={(e) =>
                  setEmail(e.target.value)
                }
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
                  setFile(
                    e.target.files?.[0] || null
                  )
                }
              />

              {file && (
                <div className="file-info">
                  Selected: {file.name}

                  <button
                    type="button"
                    onClick={() => {
                      setFile(null);

                      document.getElementById(
                        "email-file"
                      ).value = "";
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
                {loading
                  ? "Scanning..."
                  : "Scan Email"}
              </button>
            </form>

            {error && (
              <div
                className="error-box"
                role="alert"
              >
                Error: {error}
              </div>
            )}

            {/* SCAN RESULTS */}

            {result && (
              <section className="results-card">
                <h3>Scan Results</h3>

                <div className="result-row">
                  <strong>Risk Level:</strong>

                  <span
                    style={{
                      color: getRiskColor(
                        result.risk_level
                      ),
                    }}
                  >
                    {result.risk_level || "Unknown"}
                  </span>
                </div>

                <div className="result-row">
                  <strong>Risk Score:</strong>

                  <span>
                    {result.risk_score ?? 0}/100
                  </span>
                </div>

                <div className="risk-bar">
                  <div
                    className="risk-fill"
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(
                          0,
                          Number(
                            result.risk_score
                          ) || 0
                        )
                      )}%`,
                      backgroundColor:
                        getRiskColor(
                          result.risk_level
                        ),
                    }}
                  />
                </div>

                <div className="result-row">
                  <strong>Subject:</strong>

                  <span>
                    {result.subject ||
                      "Not provided"}
                  </span>
                </div>

                <div className="result-row">
                  <strong>Sender:</strong>

                  <span>
                    {result.sender ===
                    "unknown@example.invalid"
                      ? "Not available (pasted email)"
                      : result.sender ||
                        "Not provided"}
                  </span>
                </div>

                {/* DETECTED WARNINGS */}

                <h4>Detected Warnings</h4>

                {result.warnings?.length > 0 ? (
                  <ul className="warnings-list">
                    {result.warnings.map(
                      (warning, index) => (
                        <li key={index}>
                          {warning}
                        </li>
                      )
                    )}
                  </ul>
                ) : (
                  <p>
                    No phishing indicators detected.
                  </p>
                )}

                {/* NEW WEEK 4 EXPLANATIONS */}

                <PhishingExplanations
                  scan={result}
                />

                {/* DATABASE SAVE CONFIRMATION */}

                {result.scan_id != null && (
                  <p className="scan-id">
                    Saved to database — Scan ID:{" "}
                    {result.scan_id}
                  </p>
                )}
              </section>
            )}
          </>
        )}

        {/* ===================================
            PAGE 2 - SECURITY DASHBOARD
           =================================== */}

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
                {dashboardLoading
                  ? "Loading..."
                  : "Refresh"}
              </button>
            </div>

            {dashboardError && (
              <div
                className="error-box"
                role="alert"
              >
                {dashboardError}
              </div>
            )}

            {/* STATISTICS */}

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
                    <strong className="high-text">
                      {high}
                    </strong>
                  </div>

                  <div className="stat-card">
                    <span>Low Risk</span>
                    <strong className="low-text">
                      {low}
                    </strong>
                  </div>
                </div>

                {/* RISK DISTRIBUTION */}

                <div className="dashboard-panel">
                  <h3>Risk Distribution</h3>

                  {total > 0 ? (
                    <>
                      <div className="distribution-bar">

                        <div
                          className="distribution-high"
                          style={{
                            width: `${
                              (high / total) * 100
                            }%`,
                          }}
                        />

                        <div
                          className="distribution-medium"
                          style={{
                            width: `${
                              (medium / total) * 100
                            }%`,
                          }}
                        />

                        <div
                          className="distribution-low"
                          style={{
                            width: `${
                              (low / total) * 100
                            }%`,
                          }}
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
                    <p>
                      No scans recorded yet.
                    </p>
                  )}
                </div>
              </>
            )}

            {/* RECENT SCAN HISTORY */}

            <div className="dashboard-panel">
              <h3>Recent Scan History</h3>

              {dashboardLoading && (
                <p>Loading history...</p>
              )}

              {!dashboardLoading &&
              history.length === 0 ? (
                <p>
                  No scan history available.
                </p>
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

                          <td>
                            {formatDate(
                              scan.scan_date
                            )}
                          </td>

                          <td>
                            {scan.risk_score}/100
                          </td>

                          <td>
                            <RiskBadge
                              level={
                                scan.risk_level
                              }
                            />
                          </td>

                          <td>
                            {scan.warning_count ?? 0}

                            {scan.warnings?.length >
                              0 && (
                              <details>
                                <summary>
                                  View warnings
                                </summary>

                                <ul>
                                  {scan.warnings.map(
                                    (
                                      warning,
                                      index
                                    ) => (
                                      <li key={index}>
                                        {warning}
                                      </li>
                                    )
                                  )}
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

        {/* ===================================
            PAGE 3 - DATABASE EXPLORER
           =================================== */}

        {activeTab === "database" && (
          <section className="database-explorer">

            <div className="dashboard-heading">
              <div>
                <h2>Database Explorer</h2>

                <p className="description">
                  Browse, search and inspect saved phishing scans.
                </p>
              </div>

              <button
                className="refresh-button"
                onClick={loadDashboard}
                disabled={dashboardLoading}
              >
                {dashboardLoading
                  ? "Loading..."
                  : "Refresh Records"}
              </button>
            </div>

            {dashboardError && (
              <div
                className="error-box"
                role="alert"
              >
                {dashboardError}
              </div>
            )}

            {/* DATABASE SUMMARY */}

            <div className="database-summary">

              <div className="database-summary-item">
                <span>Saved Scans</span>
                <strong>
                  {history.length}
                </strong>
              </div>

              <div className="database-summary-item">
                <span>Matching Records</span>
                <strong>
                  {filteredHistory.length}
                </strong>
              </div>

              <div className="database-summary-item">
                <span>High Risk Records</span>

                <strong className="high-text">
                  {history.filter(
                    (scan) =>
                      scan.risk_level ===
                      "High"
                  ).length}
                </strong>
              </div>
            </div>

            {/* SEARCH AND FILTER CONTROLS */}

            <div className="database-controls">

              <div className="database-control">
                <label htmlFor="database-search">
                  Search Records
                </label>

                <input
                  id="database-search"
                  type="search"
                  placeholder="Search ID, score or warning..."
                  value={search}
                  onChange={(e) =>
                    setSearch(e.target.value)
                  }
                />
              </div>

              <div className="database-control">
                <label htmlFor="risk-filter">
                  Risk Level
                </label>

                <select
                  id="risk-filter"
                  value={riskFilter}
                  onChange={(e) =>
                    setRiskFilter(
                      e.target.value
                    )
                  }
                >
                  <option value="All">
                    All Risks
                  </option>

                  <option value="High">
                    High
                  </option>

                  <option value="Medium">
                    Medium
                  </option>

                  <option value="Low">
                    Low
                  </option>
                </select>
              </div>

              <div className="database-control">
                <label htmlFor="database-sort">
                  Sort By
                </label>

                <select
                  id="database-sort"
                  value={sortOrder}
                  onChange={(e) =>
                    setSortOrder(
                      e.target.value
                    )
                  }
                >
                  <option value="newest">
                    Newest First
                  </option>

                  <option value="oldest">
                    Oldest First
                  </option>

                  <option value="highest">
                    Highest Score
                  </option>

                  <option value="lowest">
                    Lowest Score
                  </option>
                </select>
              </div>
            </div>

            {/* DATABASE RECORDS */}

            <div className="dashboard-panel">

              <div className="database-table-heading">
                <h3>Saved Email Scans</h3>

                <span>
                  {filteredHistory.length} records
                </span>
              </div>

              {dashboardLoading && (
                <p>Loading database...</p>
              )}

              {!dashboardLoading &&
                filteredHistory.length === 0 && (
                  <p className="database-empty">
                    No matching records found.
                  </p>
                )}

              {!dashboardLoading &&
                filteredHistory.length > 0 && (
                  <div className="table-wrapper">

                    <table className="history-table database-table">
                      <thead>
                        <tr>
                          <th>Scan ID</th>
                          <th>Date</th>
                          <th>Score</th>
                          <th>Risk Level</th>
                          <th>Warnings</th>
                          <th>Details</th>
                        </tr>
                      </thead>

                      <tbody>
                        {filteredHistory.map(
                          (scan) => (
                            <tr key={scan.id}>

                              <td>
                                #{scan.id}
                              </td>

                              <td>
                                {formatDate(
                                  scan.scan_date
                                )}
                              </td>

                              <td>
                                <strong>
                                  {scan.risk_score}
                                  /100
                                </strong>
                              </td>

                              <td>
                                <RiskBadge
                                  level={
                                    scan.risk_level
                                  }
                                />
                              </td>

                              <td>
                                {scan.warning_count ??
                                  0}
                              </td>

                              <td>
                                <button
                                  className="details-button"
                                  onClick={() =>
                                    setSelectedScan(
                                      selectedScan ===
                                        scan.id
                                        ? null
                                        : scan.id
                                    )
                                  }
                                >
                                  {selectedScan ===
                                  scan.id
                                    ? "Hide Details"
                                    : "View Details"}
                                </button>

                                {selectedScan ===
                                  scan.id && (
                                  <div className="database-details">

                                    <h4>
                                      Scan #{scan.id}
                                    </h4>

                                    <p>
                                      <strong>
                                        Date:
                                      </strong>{" "}
                                      {formatDate(
                                        scan.scan_date
                                      )}
                                    </p>

                                    <p>
                                      <strong>
                                        Risk Score:
                                      </strong>{" "}
                                      {scan.risk_score}
                                      /100
                                    </p>

                                    <p>
                                      <strong>
                                        Risk Level:
                                      </strong>{" "}
                                      {scan.risk_level}
                                    </p>

                                    <h4>
                                      Detected Warnings
                                    </h4>

                                    {scan.warnings
                                      ?.length > 0 ? (
                                      <ul>
                                        {scan.warnings.map(
                                          (
                                            warning,
                                            index
                                          ) => (
                                            <li
                                              key={
                                                index
                                              }
                                            >
                                              {
                                                warning
                                              }
                                            </li>
                                          )
                                        )}
                                      </ul>
                                    ) : (
                                      <p>
                                        No warnings
                                        recorded.
                                      </p>
                                    )}

                                  </div>
                                )}
                              </td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
            </div>
          </section>
        )}
      </main>

      {/* FOOTER */}

      <footer className="footer">
        Phishing Email Detector — Cybersecurity Project
      </footer>
    </div>
  );
}

export default App;
