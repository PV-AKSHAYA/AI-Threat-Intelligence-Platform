

import { useState, useEffect } from "react";
import axios from "axios";
import { Activity, ShieldCheck } from "lucide-react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import ThreatInputCard from "../components/ThreatInputCard";
import RecentAnalysesTable from "../components/RecentAnalysesTable";
import DashboardStats from "../components/DashboardStats";

function Dashboard() {
  const navigate = useNavigate();

  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [analyses, setAnalyses] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const fetchAnalyses = async () => {
    try {

      const response = await axios.get(
        "http://127.0.0.1:8000/api/analyses"
      );

      setAnalyses(response.data.analyses);

    } catch (error) {
      console.error(error);
    }
  };

  const analyzeThreat = async () => {
    if (loading) return;

    if (!content.trim()) {
  toast.error(
    "Please enter threat intelligence data"
  );
  return;
}

  setLoading(true);
  const toastId = toast.loading("Analyzing threat intelligence...");

  try {
    setError("");   // add this line

   const response = await axios.post(
      "http://127.0.0.1:8000/api/analyze-threat",
      {
         input_type: "text",
         content: content,
         options: {
            mitre_mapping: true,
            generate_rules: true,
            risk_scoring: true
         }
      }
   );

   toast.success(
      "Threat analysis completed",
      { id: toastId }
   );

   fetchAnalyses();
   navigate(`/analysis/${response.data.analysis_id}`);

} catch (error) {

   console.error(error);
   setError(
    error.response?.data?.detail ||
    "Threat analysis failed. Please try again."
  );
   toast.error(
    error.response?.data?.detail ||
    "Threat analysis failed. Please try again.",
    { id: toastId }
  );

} finally {

   setLoading(false);

}
  }; // <-- Added this missing closing bracket for analyzeThreat
  const analyzeFile = async (file) => {

  if (loading || !file) return;

  setLoading(true);
  const toastId = toast.loading("Analyzing uploaded file...");

  try {

    setError("");

    const formData =
      new FormData();

    formData.append(
      "file",
      file
    );

    const response =
      await axios.post(
        "http://127.0.0.1:8000/api/analyze-threat/upload",
        formData,
        {
          headers: {
            "Content-Type":
              "multipart/form-data"
          }
        }
      );

    toast.success(
      "Threat analysis completed",
      { id: toastId }
    );

    fetchAnalyses();
    navigate(`/analysis/${response.data.analysis_id}`);

  } catch (error) {

    console.error(error);

    setError(
      error.response?.data?.detail ||
      "File analysis failed."
    );
    toast.error(
      error.response?.data?.detail ||
      "File analysis failed.",
      { id: toastId }
    );

  } finally {

    setLoading(false);

  }
};

  return (
    <div
      className="soc-page soc-page--dashboard"
    >
      <header className="soc-header">
        <div>
          <div className="soc-eyebrow">
            <ShieldCheck size={16} />
            SOC Intelligence Console
          </div>
          <Link to="/" style={{ color: "inherit", textDecoration: "none" }}>
            <h1>
              AI Threat Intelligence Platform
            </h1>
          </Link>
          <p className="soc-subtitle">
            Submit reports, extract indicators, map adversary behavior, and review recent investigations from one operational workspace.
          </p>
        </div>

        <div className="soc-actions">
          <span className="soc-badge soc-badge--neutral">
            <Activity size={14} />
            Live Analysis
          </span>
        </div>
      </header>

      <ThreatInputCard
  content={content}
  setContent={setContent}
  loading={loading}
  analyzeThreat={analyzeThreat}
  analyzeFile={analyzeFile}
  error={error}
/>
<DashboardStats analyses={analyses} />
<RecentAnalysesTable
  analyses={analyses}
/>

    </div>
  );
}

export default Dashboard;
