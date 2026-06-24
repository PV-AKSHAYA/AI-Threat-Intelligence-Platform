import { Crosshair } from "lucide-react";

function MitreAttackChain({ techniques }) {
  if (!techniques || techniques.length === 0) {
    return <p className="soc-empty">No MITRE mappings found.</p>;
  }

  const getConfidenceClass = (confidence) => {
    switch (confidence?.toLowerCase()) {
      case "high":
        return "soc-badge soc-badge--critical";
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
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Crosshair className="soc-icon" />
            MITRE ATT&CK Chain
          </h2>
          <p className="soc-muted">
            Techniques and tactics associated with the observed behavior.
          </p>
        </div>
      </div>

      <div className="mitre-grid">
        {techniques.map((technique, index) => (
          <div
            key={index}
            className="mitre-card"
          >
            <div className="mitre-card__top">
              <code className="soc-code">
                {technique.id}
              </code>
              <span className={getConfidenceClass(technique.confidence)}>
                {technique.confidence}
              </span>
            </div>

            <h3>{technique.technique}</h3>

            <p className="mitre-card__label">Tactic</p>
            <p className="mitre-card__tactic">
              {technique.tactic}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default MitreAttackChain;
