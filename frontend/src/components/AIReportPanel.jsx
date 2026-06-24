import { ClipboardCheck, FileText } from "lucide-react";

function AIReportPanel({ report }) {
  if (!report) {
    return <p className="soc-empty">No AI report available.</p>;
  }

  return (
    <div className="soc-card ai-report">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <FileText className="soc-icon" />
            AI Threat Intelligence Report
          </h2>
          <p className="soc-muted">
            Analyst-ready narrative and recommended response actions.
          </p>
        </div>
      </div>

      <Section
        title="Executive Summary"
        content={report.summary}
      />

      <Section
        title="Attack Scenario"
        content={report.attack_scenario}
      />

      <Section
        title="Business Impact"
        content={report.business_impact}
      />

      <ListSection
        title="Immediate Actions"
        items={report.immediate_actions}
      />

      <ListSection
        title="Long-Term Remediation"
        items={report.long_term_remediation}
      />

      <ListSection
        title="Monitoring Recommendations"
        items={report.monitoring}
      />
    </div>
  );
}

function Section({ title, content }) {
  return (
    <section className="report-section">
      <h3>{title}</h3>
      <p>{content}</p>
    </section>
  );
}

function ListSection({ title, items }) {
  if (!items || items.length === 0) return null;

  return (
    <section className="report-section">
      <h3>{title}</h3>

      <ul className="report-list">
        {items.map((item, index) => (
          <li key={index}>
            <ClipboardCheck size={17} />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default AIReportPanel;
