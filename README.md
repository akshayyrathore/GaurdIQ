# Percepta - AI Brain for WAF

**Percepta** is an autonomous AI security brain that sits on top of existing Web Application Firewalls. It uses an Agentic AI approach to **Observe**, **Reason**, and **Decide** on security threats in real-time.

## 🚀 Features

- **AI-Powered Analysis**: Uses RAG (Retrieval Augmented Generation) to compare requests against OWASP patterns and past incidents.
- **Anomaly Detection**: Unsupervised Learning (Isolation Forest) to detect zero-day attacks.
- **Agentic Decisions**: Probabilistic decision making (Allow, Block, Challenge) based on risk scores.
- **Real-time HUD**: Futuristic dashboard with live traffic visualization using Next.js & Framer Motion.

## 🛠️ Tech Stack

- **Backend**: Python, FastAPI, SQLModel, Scikit-learn, ChromaDB
- **Frontend**: Next.js 14, Tailwind CSS, Framer Motion, Lucide Icons

## 🏃‍♂️ How to Run

### Prerequisite
Ensure you have Python 3.10+ and Node.js 18+ installed.

### 1. Start the Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```
The API will run at `http://127.0.0.1:8000`.
Docs available at `http://127.0.0.1:8000/docs`.

### 2. Start the Frontend
Open a new terminal:
```bash
cd frontend
npm install # if not already installed
npm run dev
```
The UI will run at `http://localhost:3000`.

## 🧪 Demo Flow

1. **Open Dashboard**: Go to `localhost:3000/dashboard`.
2. **Simulate Traffic**:
   - The dashboard automatically fetches traffic from the backend.
   - To inject dummy data, use Swagger (`/docs`) to POST to `/api/logs/ingest`.
   - The `TrafficVisualizer` creates animated particles to simulate flow.
3. **View Incidents**: Click on any row in the "Recent Decisions" table to view the **AI Explanation Panel**.

## 📂 Project Structure

- `backend/agents`: Decision logic.
- `backend/ml`: Anomaly detection models.
- `backend/rag`: Vector database interactions.
- `frontend/components`: UI components.

---
Built with ❤️ by Antigravity AI.
