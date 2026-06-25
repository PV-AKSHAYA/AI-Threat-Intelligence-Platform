function RiskGauge({ score, level, riskLevel }) {
  const normalizedScore = Math.max(0, Math.min(Number(score ?? 0), 100));
  const percentage = normalizedScore / 100;
  const displayLevel = (riskLevel ?? level ?? "UNKNOWN")
    .toString()
    .toUpperCase();

  const gaugeColor = {
    LOW: "#22C55E",
    MEDIUM: "#EAB308",
    HIGH: "#F97316",
    CRITICAL: "#EF4444"
  }[displayLevel] || "#22C55E";

  const size = 280;
  const center = size / 2;
  const radius = 110;
  const strokeWidth = 20;
  const arcLength = Math.PI * radius;
  const dashOffset = arcLength * (1 - percentage);
  const angle = -180 + percentage * 180;
  const pointerLength = radius - 26;
  const pointerX = center + Math.cos((angle * Math.PI) / 180) * pointerLength;
  const pointerY = center + Math.sin((angle * Math.PI) / 180) * pointerLength;
  const pathD = `M ${center - radius} ${center} A ${radius} ${radius} 0 0 1 ${center + radius} ${center}`;

  return (
    <div className="soc-card risk-gauge-card">
      <h2>Risk Score</h2>

      <div
        style={{
          width: "100%",
          height: 300,
          display: "flex",
          alignItems: "center",
          justifyContent: "center"
        }}
      >
        <svg
          width="100%"
          height="300"
          viewBox={`0 0 ${size} ${size}`}
          preserveAspectRatio="xMidYMid meet"
        >
          <path
            d={pathD}
            fill="none"
            stroke="#1F2937"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          <path
            d={pathD}
            fill="none"
            stroke={gaugeColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={arcLength}
            strokeDashoffset={dashOffset}
            style={{ transition: "stroke-dashoffset 0.6s ease" }}
          />
          <line
            x1={center}
            y1={center}
            x2={pointerX}
            y2={pointerY}
            stroke={gaugeColor}
            strokeWidth={4}
            strokeLinecap="round"
            style={{
              transformOrigin: `${center}px ${center}px`,
              transform: `rotate(${angle}deg)`,
              transition: "transform 0.6s ease"
            }}
          />
          <circle cx={center} cy={center} r={8} fill={gaugeColor} />
        </svg>
      </div>

      <h1 className="risk-gauge-card__score">
        {`${Math.round(normalizedScore)} / 100`}
      </h1>

      <h3 className="risk-gauge-card__level" style={{ color: gaugeColor }}>
        {displayLevel}
      </h3>
    </div>
  );
}

export default RiskGauge;
