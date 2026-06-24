import { Bug, Crosshair, DatabaseZap, ShieldAlert } from "lucide-react";

function StatCard({ title, value, subtitle, icon: Icon, tone }) {
  return (
    <div className={`stat-card stat-card--${tone}`}>
      <div className="stat-card__icon">
        <Icon size={22} />
      </div>

      <div>
        <p className="stat-card__title">{title}</p>
        <strong className="stat-card__value">{value}</strong>
        <p className="stat-card__subtitle">{subtitle}</p>
      </div>
    </div>
  );
}

function DashboardStats({ analyses }) {
  const totalAnalyses = analyses.length;

  const criticalThreats = analyses.filter(
    (a) => a.risk_level === "critical"
  ).length;

  const maliciousIOCs = analyses.reduce(
    (count, a) => count + (a.iocs_count || 0),
    0
  );

  const mitreTechniques = analyses.reduce(
    (count, a) => count + (a.mitre_count || 0),
    0
  );

  return (
    <div className="soc-grid soc-grid--cards stats-grid">
      <StatCard
        title="Total Analyses"
        value={totalAnalyses}
        subtitle="Completed investigations"
        icon={DatabaseZap}
        tone="blue"
      />

      <StatCard
        title="Critical Threats"
        value={criticalThreats}
        subtitle="Immediate attention"
        icon={ShieldAlert}
        tone="red"
      />

      <StatCard
        title="Malicious IOCs"
        value={maliciousIOCs}
        subtitle="Extracted indicators"
        icon={Bug}
        tone="amber"
      />

      <StatCard
        title="MITRE Techniques"
        value={mitreTechniques}
        subtitle="Mapped behaviors"
        icon={Crosshair}
        tone="green"
      />
    </div>
  );
}

export default DashboardStats;
