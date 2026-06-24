import { Clipboard, Code2 } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";

function DetectionRulesTabs({ rules }) {
  const [activeTab, setActiveTab] = useState("sigma");

  const tabs = [
    "sigma",
    "yara",
    "splunk",
    "sentinel_kql",
    "elastic"
  ];

  const labels = {
    sigma: "Sigma",
    yara: "YARA",
    splunk: "Splunk",
    sentinel_kql: "Sentinel KQL",
    elastic: "Elastic"
  };

  return (
    <div className="soc-card detection-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Code2 className="soc-icon" />
            Detection Rules
          </h2>
          <p className="soc-muted">
            Generated rules for common SIEM, EDR, and detection engineering workflows.
          </p>
        </div>

        <button
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(
                rules?.[activeTab] || ""
              );
              toast.success(`${labels[activeTab]} rule copied`);
            } catch (error) {
              console.error("Clipboard Error:", error);
              toast.error("Unable to copy rule");
            }
          }}
          className="soc-button"
        >
          <Clipboard size={18} />
          Copy Rule
        </button>
      </div>

      <div className="rule-tabs">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`rule-tab ${activeTab === tab ? "rule-tab--active" : ""}`}
          >
            {labels[tab]}
          </button>
        ))}
      </div>

      <div className="rule-viewer">
        <div className="rule-viewer__bar">
          <span>{labels[activeTab]}</span>
          <span>{activeTab}</span>
        </div>

        <pre>
          {rules?.[activeTab] || "No rule available"}
        </pre>
      </div>
    </div>
  );
}

export default DetectionRulesTabs;
