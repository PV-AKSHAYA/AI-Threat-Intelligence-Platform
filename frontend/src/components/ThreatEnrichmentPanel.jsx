import { Bug, Globe2, MapPin, Network, Server, ShieldUser } from "lucide-react";

function ThreatEnrichmentPanel({ enrichment }) {
  if (!enrichment) {
    return <p className="soc-empty">No enrichment data available.</p>;
  }

  return (
    <div className="soc-card">
      <div className="soc-card__header">
        <div>
          <h2 className="soc-card__title">
            <Server className="soc-icon" />
            Threat Enrichment
          </h2>
          <p className="soc-muted">
            Context from vulnerability, domain, and IP intelligence.
          </p>
        </div>
      </div>

      {enrichment.cves?.length > 0 && (
        <EnrichmentSection title="Vulnerabilities" icon={Bug}>
          {enrichment.cves.map((cve, index) => (
            <div
              key={index}
              className="enrichment-card"
            >
              <h3>{cve.id}</h3>

              <Metric label="CVSS" value={cve.cvss} />
              <Metric label="Severity" value={cve.severity} />
              <Metric
                label="Exploit"
                value={
                  cve.exploit_available
                    ? "Available"
                    : "Not Known"
                }
              />
              <Metric
                label="Threat Actors"
                value={cve.threat_actors?.join(", ")}
                icon={ShieldUser}
              />
            </div>
          ))}
        </EnrichmentSection>
      )}

      {enrichment.domains?.length > 0 && (
        <EnrichmentSection title="Domains" icon={Globe2}>
          {enrichment.domains.map((domain, index) => (
            <div
              key={index}
              className="enrichment-card"
            >
              <h3>{domain.value}</h3>

              <Metric label="Reputation" value={domain.reputation} />
              <Metric label="Threat Type" value={domain.threat_type} />
              <Metric
                label="Threat Actors"
                value={domain.threat_actors?.join(", ")}
                icon={ShieldUser}
              />
              <Metric
                label="Country"
                value={domain.country}
                icon={MapPin}
              />
            </div>
          ))}
        </EnrichmentSection>
      )}

      {enrichment.ips?.length > 0 && (
        <EnrichmentSection title="IP Intelligence" icon={Network}>
          {enrichment.ips.map((ip, index) => (
            <div
              key={index}
              className="enrichment-card"
            >
              <h3>{ip.value}</h3>

              <Metric label="Category" value={ip.category} />
              <Metric label="Threat" value={ip.threat_type} />
              <Metric label="ASN" value={ip.asn} icon={Network} />
              <Metric label="ISP" value={ip.isp} />
              <Metric label="Country" value={ip.country} icon={MapPin} />
            </div>
          ))}
        </EnrichmentSection>
      )}
    </div>
  );
}

function EnrichmentSection({ title, icon: Icon, children }) {
  return (
    <section className="enrichment-section">
      <h3 className="enrichment-section__title">
        <Icon size={18} />
        {title}
      </h3>

      <div className="enrichment-grid">
        {children}
      </div>
    </section>
  );
}

function Metric({ label, value, icon: Icon }) {
  return (
    <p className="enrichment-metric">
      {Icon && <Icon size={15} />}
      <span>{label}</span>
      <strong>{value}</strong>
    </p>
  );
}

export default ThreatEnrichmentPanel;
