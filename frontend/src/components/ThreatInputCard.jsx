import { FileUp, Loader2, Radar, Send, TriangleAlert } from "lucide-react";

function ThreatInputCard({
  content,
  setContent,
  loading,
  analyzeThreat,
  analyzeFile,
  error
}) {
  return (
    <div className="soc-card threat-input-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Radar className="soc-icon" />
            Analyze Threat
          </h2>
          <p className="soc-muted">
            Paste intelligence text or upload a supported file for enrichment, scoring, MITRE mapping, and detection output.
          </p>
        </div>
      </div>

      <textarea
        rows="8"
        className="soc-textarea"
        placeholder="Paste threat intelligence report..."
        value={content}
        disabled={loading}
        onChange={(e) =>
          setContent(e.target.value)
        }
      />

      <div className="threat-input-actions">
        <label
          className={`file-upload-control ${loading ? "file-upload-control--disabled" : ""}`}
          aria-disabled={loading}
        >
          <FileUp size={18} />
          <span>{loading ? "Upload Disabled" : "Upload File"}</span>
          <input
            type="file"
            accept=".pdf,.docx,.txt,.csv,.json"
            disabled={loading}
            onChange={(e) =>
              !loading &&
              analyzeFile(
                e.target.files?.[0]
              )
            }
          />
        </label>

        <button
          onClick={analyzeThreat}
          disabled={loading}
          className="soc-button"
        >
          {loading ? (
            <Loader2 size={18} className="spin" />
          ) : (
            <Send size={18} />
          )}
          {loading
            ? "Analyzing..."
            : "Analyze Threat"}
        </button>
      </div>

      {error && (
        <div className="soc-alert">
          <TriangleAlert size={18} />
          {error}
        </div>
      )}

      {loading && (
        <div className="soc-progress">
          <Loader2 size={18} className="spin" />
          Analyzing Threat Intelligence...
        </div>
      )}
    </div>
  );
}

export default ThreatInputCard;
