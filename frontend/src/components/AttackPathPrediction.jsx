import { ArrowRight, Route } from "lucide-react";

function AttackPathPrediction({ techniques = [] }) {
  const attackStages = [];

  const mapping = {
    T1190: "Initial Access",
    T1566: "Phishing",
    T1068: "Privilege Escalation",
    T1003: "Credential Access",
    T1071: "Command & Control",
    T1041: "Data Exfiltration",
    T1486: "Impact (Ransomware)"
  };

  techniques.forEach((tech) => {
    const stage =
      mapping[tech.technique_id] ||
      mapping[tech.id];

    if (
      stage &&
      !attackStages.includes(stage)
    ) {
      attackStages.push(stage);
    }
  });

  return (
    <div className="soc-card attack-path-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Route className="soc-icon" />
            Predicted Attack Path
          </h2>
          <p className="soc-muted">
            Probable sequence inferred from mapped techniques.
          </p>
        </div>
      </div>

      <div className="attack-path">
        {attackStages.map(
          (stage, index) => (
            <div
              key={index}
              className="attack-path__item"
            >
              <div className="attack-path__stage">
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{stage}</strong>
              </div>

              {index <
                attackStages.length -
                  1 && (
                <ArrowRight className="attack-path__arrow" />
              )}
            </div>
          )
        )}
      </div>
    </div>
  );
}

export default AttackPathPrediction;
