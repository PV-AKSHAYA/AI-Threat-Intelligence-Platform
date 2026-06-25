import { Link } from "react-router-dom";

function NotFound() {
  return (
    <div className="soc-page" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div
        className="soc-card"
        style={{
          maxWidth: "560px",
          width: "100%",
          textAlign: "center",
          padding: "40px"
        }}
      >
        <h1 style={{ fontSize: "3.5rem", marginBottom: "12px" }}>404</h1>
        <h2 style={{ marginBottom: "12px" }}>Page Not Found</h2>
        <p style={{ marginBottom: "24px" }}>
          The page you're looking for doesn't exist.
        </p>
        <Link to="/" className="soc-button" style={{ textDecoration: "none" }}>
          ← Return to Dashboard
        </Link>
      </div>
    </div>
  );
}

export default NotFound;
