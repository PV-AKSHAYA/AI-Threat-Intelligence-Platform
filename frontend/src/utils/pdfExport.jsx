import jsPDF from "jspdf";

export function exportThreatPDF(analysis) {
  const doc = new jsPDF();

  let y = 20;

  doc.setFontSize(18);
  doc.text(
    "AI Threat Intelligence Report",
    20,
    y
  );

  y += 15;

  doc.setFontSize(12);

  doc.text(
    `Risk Score: ${analysis.risk_score}`,
    20,
    y
  );

  y += 10;

  doc.text(
    `Risk Level: ${analysis.risk_level}`,
    20,
    y
  );

  y += 15;

  doc.text(
    "Executive Summary:",
    20,
    y
  );

  y += 10;

  const summary =
    doc.splitTextToSize(
      analysis.ai_report?.summary ||
        "",
      170
    );

  doc.text(summary, 20, y);

  y += summary.length * 7 + 10;

  doc.text(
    "IOCs:",
    20,
    y
  );

  y += 10;

  analysis.iocs?.forEach((ioc) => {
    doc.text(
      `${ioc.type}: ${ioc.value}`,
      25,
      y
    );
    y += 8;
  });

  doc.save(
    `Threat_Report_${analysis.analysis_id}.pdf`
  );
}