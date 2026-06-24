import React from "react";
import ReactFlow, { Background, Controls } from "reactflow";
import { Share2 } from "lucide-react";
import "reactflow/dist/style.css";

function IOCGraph({ analysis }) {
  const nodes = [
    {
      id: "threat",
      data: {
        label: "Threat Analysis"
      },
      position: {
        x: 450,
        y: 40
      },
      style: {
        background: "#111827",
        color: "#f9fafb",
        border: "2px solid #3b82f6",
        borderRadius: "16px",
        width: 240,
        padding: 14,
        textAlign: "center",
        boxShadow: "0 18px 40px rgba(37, 99, 235, 0.22)"
      }
    }
  ];

  const edges = [];

  analysis?.iocs?.forEach((ioc, index) => {
    let borderColor = "#3b82f6";
    let background = "#13213a";

    if (ioc.reputation === "critical") {
      borderColor = "#ef4444";
      background = "#2a1218";
    } else if (ioc.reputation === "malicious") {
      borderColor = "#f59e0b";
      background = "#261c10";
    }

    nodes.push({
      id: `ioc-${index}`,
      data: {
        label: `${ioc.type}: ${ioc.value}`
      },
      position: {
        x: 80 + (index % 4) * 280,
        y: 230 + Math.floor(index / 4) * 145
      },
      style: {
        background,
        color: "#f9fafb",
        border: `1px solid ${borderColor}`,
        borderRadius: "14px",
        width: 230,
        padding: 12,
        textAlign: "center",
        boxShadow: "0 14px 30px rgba(0, 0, 0, 0.24)"
      }
    });

    edges.push({
      id: `edge-${index}`,
      source: "threat",
      target: `ioc-${index}`,
      animated: true,
      style: {
        stroke: borderColor,
        strokeWidth: 2
      }
    });
  });

  return (
    <div className="soc-card graph-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Share2 className="soc-icon" />
            IOC Relationship Graph
          </h2>
          <p className="soc-muted">
            Relationship view of extracted indicators connected to this analysis.
          </p>
        </div>
      </div>

      <div className="graph-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1f2937" gap={22} />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}

export default IOCGraph;
