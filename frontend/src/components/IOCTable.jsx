import { Clipboard, Copy, ListChecks } from "lucide-react";
import toast from "react-hot-toast";

function IOCTable({ iocs }) {
  const copyToClipboard = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
      console.log("Copied:", value);
      toast.success("IOC copied");
    } catch (err) {
      console.error("Clipboard Error:", err);

      const textArea = document.createElement("textarea");
      textArea.value = value;
      document.body.appendChild(textArea);

      textArea.select();
      document.execCommand("copy");

      document.body.removeChild(textArea);

      console.log("Copied using fallback");
      toast.success("IOC copied");
    }
  };

  const getBadgeClass = (reputation) => {
    switch (reputation?.toLowerCase()) {
      case "malicious":
        return "soc-badge soc-badge--malicious";
      case "critical":
        return "soc-badge soc-badge--critical";
      case "suspicious":
        return "soc-badge soc-badge--suspicious";
      case "clean":
        return "soc-badge soc-badge--clean";
      case "benign":
        return "soc-badge soc-badge--benign";
      default:
        return "soc-badge soc-badge--neutral";
    }
  };

  const copyAllIOCs = async () => {
    const text = (iocs || [])
      .map((ioc) => ioc.value)
      .join("\n");

    try {
      await navigator.clipboard.writeText(text);
      console.log("IOCs copied");
      toast.success("IOCs copied");
    } catch (err) {
      console.error("Clipboard Error:", err);
      toast.error("Unable to copy IOCs");
    }
  };

  return (
    <div className="soc-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <ListChecks className="soc-icon" />
            Extracted IOCs ({iocs?.length || 0})
          </h2>
          <p className="soc-muted">
            Indicators extracted from the submitted intelligence.
          </p>
        </div>

        <button
          onClick={copyAllIOCs}
          className="soc-button"
        >
          <Clipboard size={18} />
          Copy All IOCs
        </button>
      </div>

      <div className="soc-table-wrap">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Reputation</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {iocs?.map((ioc, index) => (
              <tr key={index}>
                <td>{ioc.type}</td>

                <td>
                  <code className="soc-code">{ioc.value}</code>
                </td>

                <td>
                  <span className={getBadgeClass(ioc.reputation)}>
                    {ioc.reputation}
                  </span>
                </td>

                <td>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        ioc.value
                      )
                    }
                    className="soc-button soc-button--ghost"
                  >
                    <Copy size={14} />
                    Copy
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default IOCTable;
