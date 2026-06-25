

// import { Routes, Route } from "react-router-dom";

// import Dashboard from "./pages/Dashboard";
// import AnalysisResult from "./pages/AnalysisResult";
// import IOCGraph from "./pages/IOCGraph";
// import MitreMatrix from "./pages/MitreMatrix";

// function App() {
//   return (
//     <Routes>
//       <Route path="/" element={<Dashboard />} />
//       <Route path="/analysis/:id" element={<AnalysisResult />} />
//       <Route path="/ioc-graph" element={<IOCGraph />} />
//       <Route path="/mitre-matrix" element={<MitreMatrix />} />
//     </Routes>
//   );
// }

// export default App;

// function App() {
//   return (
//     <div style={{ padding: "50px", color: "white" }}>
//       <h1>Frontend Working ✅</h1>
//     </div>
//   );
// }

// export default App;

// function App() {
//   console.log("APP LOADED");

//   return (
//     <div
//       style={{
//         background: "red",
//         color: "white",
//         minHeight: "100vh",
//         fontSize: "40px",
//         padding: "50px"
//       }}
//     >
//       FRONTEND WORKING
//     </div>
//   );
// }

// export default App;

// import Dashboard from "./pages/Dashboard";

// function App() {
//   return <Dashboard />;
// }

// export default App;


// import { BrowserRouter, Routes, Route } from "react-router-dom";

// import Dashboard from "./pages/Dashboard";
// import AnalysisResult from "./pages/AnalysisResult";

// function App() {
//   return (
//     <BrowserRouter>
//       <Routes>
//         <Route path="/" element={<Dashboard />} />
//         <Route
//           path="/analysis/:analysisId"
//           element={<AnalysisResult />}
//         />
//       </Routes>
//     </BrowserRouter>
//   );
// }

// export default App;

import { Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import AnalysisResult from "./pages/AnalysisResult";
import NotFound from "./pages/NotFound";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route
        path="/analysis/:analysisId"
        element={<AnalysisResult />}
      />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default App;