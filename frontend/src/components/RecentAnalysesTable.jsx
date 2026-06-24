import { Search, TableProperties } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useState } from "react";

function RecentAnalysesTable({ analyses }) {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const filteredAnalyses = analyses.filter((item) =>
    item.analysis_id
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const getRiskBadgeClass = (level) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "soc-badge soc-badge--critical";
      case "high":
        return "soc-badge soc-badge--high";
      case "medium":
        return "soc-badge soc-badge--medium";
      case "low":
        return "soc-badge soc-badge--low";
      default:
        return "soc-badge soc-badge--neutral";
    }
  };

  return (
    <div className="soc-card">
      <div className="soc-card__header recent-table-header">
        <div>
          <h2 className="soc-card__title">
            <TableProperties className="soc-icon" />
            Recent Analyses
          </h2>
          <p className="soc-muted">
            Review completed investigations and reopen full intelligence results.
          </p>
        </div>

        <div className="soc-input-shell">
          <Search />
          <input
            type="text"
            placeholder="Search Analysis ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="soc-field"
          />
        </div>
      </div>

      <div className="soc-table-wrap">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Created</th>
              <th>ID</th>
              <th>Type</th>
              <th>Risk Score</th>
              <th>Risk Level</th>
              <th>Preview</th>
            </tr>
          </thead>

          <tbody>
            {filteredAnalyses.map((item) => (
              <tr
                key={item.analysis_id}
                onClick={() =>
                  navigate(`/analysis/${item.analysis_id}`)
                }
              >
                <td>
                  {new Date(item.timestamp)
                    .toLocaleString()}
                </td>
                <td>
                  <code className="soc-code">
                    {item.analysis_id.slice(0, 8)}
                  </code>
                </td>
                <td>{item.input_type}</td>
                <td>{item.risk_score}</td>
                <td>
                  <span className={getRiskBadgeClass(item.risk_level)}>
                    {item.risk_level}
                  </span>
                </td>
                <td>
                  {item.input_preview?.slice(0, 50)}...
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default RecentAnalysesTable;
