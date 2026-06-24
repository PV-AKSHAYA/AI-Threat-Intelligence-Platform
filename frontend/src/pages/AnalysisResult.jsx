import { useEffect, useState } from "react";
import { Download, FileJson, ShieldAlert } from "lucide-react";
import toast from "react-hot-toast";
import { useParams } from "react-router-dom";
import { getAnalysis } from "../services/api";
import RiskGauge from "../components/RiskGauge";
import AIReportPanel from "../components/AIReportPanel";
import DetectionRulesTabs from "../components/DetectionRulesTabs";
import MitreAttackChain from "../components/MitreAttackChain";
import IOCTable from "../components/IOCTable";
import ThreatEnrichmentPanel from "../components/ThreatEnrichmentPanel";
import IOCGraph from "./IOCGraph";
import AttackPathPrediction from "../components/AttackPathPrediction";
import { exportThreatPDF } from "../utils/pdfExport";

function AnalysisResult() {
  const { analysisId } = useParams();

  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");

  const exportJSON = () => {
    if (!analysis) return;

    const blob = new Blob(
      [JSON.stringify(analysis, null, 2)],
      {
        type: "application/json"
      }
    );

    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download =
      `analysis-${analysis.analysis_id}.json`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
    toast.success("JSON export downloaded");
  };

  useEffect(() => {
    const loadAnalysis = async () => {
      try {
        const response = await getAnalysis(analysisId);
        setAnalysis(response.data);
      } catch (err) {
        console.error("Failed to load analysis:", err);
      } finally {
        setLoading(false);
      }
    };

    loadAnalysis();
  }, [analysisId]);

  if (loading) {
    return (
      <div className="soc-page">
        <div className="soc-card soc-loading">
          Loading analysis...
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="soc-page">
        <div className="soc-card soc-empty">
          Analysis not found
        </div>
      </div>
    );
  }

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "intelligence", label: "Intelligence" },
    { id: "detection", label: "Detection" },
    { id: "report", label: "AI Report" }
  ];

  return (
    <div className="soc-page">
      <header className="soc-header">
        <div>
          <div className="soc-eyebrow">
            <ShieldAlert size={16} />
            Threat Analysis Details
          </div>
          <h1>Threat Analysis Details</h1>
          <p className="soc-subtitle">
            Analysis ID <code className="soc-code">{analysis.analysis_id}</code>
          </p>
        </div>

        <div className="soc-actions">
          <button
            onClick={exportJSON}
            className="soc-button soc-button--secondary"
          >
            <FileJson size={18} />
            Export JSON
          </button>

          <button
            onClick={() =>
              exportThreatPDF(
                analysis
              )
            }
            className="soc-button"
          >
            <Download size={18} />
            Download PDF
          </button>
        </div>
      </header>

      <nav className="soc-tabs" aria-label="Analysis sections">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`soc-tab ${activeTab === tab.id ? "soc-tab--active" : ""}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "overview" && (
        <>
          <div className="soc-grid soc-grid--two">
            <RiskGauge
              score={analysis.risk_score}
              level={analysis.risk_level}
            />

            <div className="soc-card risk-factors-card">
              <h2>Risk Factors</h2>

              <ul className="risk-factor-list">
                {analysis.risk_factors?.map((factor, idx) => (
                  <li key={idx}>
                    {factor.factor}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <IOCTable
            iocs={analysis.iocs}
          />

          <IOCGraph
            analysis={analysis}
          />

          <AttackPathPrediction
            techniques={
              analysis.mitre_mapping
            }
          />
        </>
      )}

      {activeTab === "intelligence" && (
        <>
          <MitreAttackChain
            techniques={analysis.mitre_mapping}
          />

          <ThreatEnrichmentPanel
            enrichment={analysis.enrichment}
          />
        </>
      )}

      {activeTab === "detection" && (
        <DetectionRulesTabs
          rules={analysis.detection_rules}
        />
      )}

      {activeTab === "report" && (
        <AIReportPanel
          report={analysis.ai_report}
        />
      )}
    </div>
  );
}

export default AnalysisResult;
