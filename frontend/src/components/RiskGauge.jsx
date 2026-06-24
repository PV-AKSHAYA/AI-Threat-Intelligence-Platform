import {
  RadialBarChart,
  RadialBar,
  Legend,
  ResponsiveContainer
} from "recharts";

function RiskGauge({ score, level }) {
  const data = [
    {
      name: level?.toUpperCase() || "UNKNOWN",
      value: score || 0,
      fill:
        score >= 81
          ? "#ef4444"
          : score >= 61
          ? "#f97316"
          : score >= 31
          ? "#eab308"
          : "#22c55e"
    }
  ];

  return (
    <div
      className="soc-card risk-gauge-card"
    >
      <h2>Risk Score</h2>

      <ResponsiveContainer width="100%" height={300}>
        <RadialBarChart
          innerRadius="70%"
          outerRadius="100%"
          data={data}
          startAngle={180}
          endAngle={0}
        >
          <RadialBar
            minAngle={15}
            background
            clockWise
            dataKey="value"
          />
          <Legend
            iconType="circle"
            wrapperStyle={{ color: "#9ca3af" }}
          />
        </RadialBarChart>
      </ResponsiveContainer>

      <h1 className="risk-gauge-card__score">
        {score}
      </h1>

      <h3
        className="risk-gauge-card__level"
        style={{
          color:
            score >= 81
              ? "#ef4444"
              : score >= 61
              ? "#f97316"
              : score >= 31
              ? "#eab308"
              : "#22c55e"
        }}
      >
        {level?.toUpperCase()}
      </h3>
    </div>
  );
}

export default RiskGauge;
