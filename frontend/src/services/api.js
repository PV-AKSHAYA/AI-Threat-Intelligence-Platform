import axios from "axios";

const API = axios.create({
  baseURL: "http://127.0.0.1:8000/api",
});

export const analyzeThreat = (payload) =>
  API.post("/analyze-threat", payload);

export const uploadThreatFile = (formData) =>
  API.post("/analyze-threat/upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

export const getAnalyses = () =>
  API.get("/analyses");

export const getAnalysis = (id) =>
  API.get(`/analyses/${id}`);

export default API;