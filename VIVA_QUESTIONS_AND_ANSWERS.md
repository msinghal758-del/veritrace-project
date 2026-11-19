# VERITRACE — COMPREHENSIVE VIVA VOCE EXAMINATION GUIDE
## Academic Defense & Technical Questions & Answers for Project Evaluation 3

**Project Title:** VeriTrace: AI-Powered Cyber Incident Response and Digital Forensics Platform  
**Target Audience:** Undergraduate / Postgraduate Capstone Evaluation Panel (External & Internal Examiners)

---

## SECTION 1: MACHINE LEARNING & DATA SCIENCE

### Q1. Why did you choose Random Forest Classifier over Deep Learning (e.g., LSTMs, CNNs) or Logistic Regression?
**Examiner's Intent:** To test if you blindly picked an algorithm or understood the trade-offs of tabular network intrusion data.

**Your Answer:**
> "We selected **Random Forest** for four technical reasons:
> 1. **Tabular Feature Space:** In network flow analysis (UNSW-NB15), data consists of heterogeneous tabular columns (durations, packet counts, TTL values, TCP window sizes). Empirical research (e.g., Grinsztajn et al., 2022) demonstrates that tree-based ensembles consistently outperform deep neural networks on tabular data without requiring massive training footprints.
> 2. **Non-Linear Interactions:** Features like source-to-destination packet ratios (`spkts`/`dpkts`) and TTL boundaries have sharp threshold behavior rather than smooth linear boundaries, making linear models like Logistic Regression inadequate.
> 3. **Sub-10ms Inference Latency:** Deep learning models introduce significant inference latency and require GPU hardware acceleration. Our fitted Random Forest evaluates a packet flow in under **8 milliseconds** on standard CPU, which is crucial for real-time SOC triage.
> 4. **Interpretability & Probability Extraction:** Random Forest provides calibrated class probabilities via leaf node voting, allowing us to display confidence scores and multiclass distributions to SOC analysts."

---

### Q2. Your Overall Accuracy is 82.87%. Why isn't it 98% or 99% like some published papers claim? Did your model fail?
**Examiner's Intent:** To catch students who either fabricate results or do not understand evaluation rigor.

**Your Answer:**
> "No, the model did not fail — **82.87% is an authentic, mathematically sound result** on the multiclass UNSW-NB15 benchmark:
> 1. **Multiclass vs. Binary Classification:** Papers claiming >95% accuracy on UNSW-NB15 are performing **binary classification** (simply differentiating Normal vs. Attack). VeriTrace performs a much harder **10-class multiclass classification** (identifying Normal, Exploits, DoS, Fuzzers, Reconnaissance, Backdoor, Analysis, Shellcode, Generic, and Worms).
> 2. **No Data Leakage:** We strictly excluded the `id` column and the binary `label` column from our feature set. Many naive implementations mistakenly include `label` or correlated sequential indices, which causes artificial 99% accuracy.
> 3. **Realistic Overlap:** Real network attacks like *Fuzzers* and *Exploits* share overlapping packet size signatures with *Generic* traffic. 82.87% reflects real-world operational performance on a strict 20% holdout test partition (35,069 unseen samples)."

---

### Q3. Explain the mathematical difference between your Macro F1-score (56.63%) and Weighted F1-score (81.24%). Why is there a big gap?
**Examiner's Intent:** To verify whether you actually calculated these metrics or just copied them.

**Your Answer:**
> "The gap is directly caused by **severe natural class imbalance** in the UNSW-NB15 dataset:
> - **Weighted F1 (81.24%)** weights each class's F1-score by its actual prevalence (support) in the test set:
>   $$\text{Weighted } F1 = \sum_{c=1}^{10} \left( \frac{\text{Support}_c}{\text{Total}} \times F1_c \right)$$
>   Because major classes like *Normal* (F1 = 87.13%, 11,200 samples) and *Generic* (F1 = 97.45%, 8,000 samples) constitute over 54% of the dataset, the weighted metric accurately reflects overall operational traffic.
> - **Macro F1 (56.63%)** is the unweighted arithmetic mean across all 10 classes:
>   $$\text{Macro } F1 = \frac{1}{10} \sum_{c=1}^{10} F1_c$$
>   This treats *Worms* (only 40 test samples, F1 = 28.57%) and *Backdoor* (349 test samples, F1 = 7.59%) with equal weight as *Normal* (11,200 samples). Because tree splits cannot easily learn robust boundaries for rare classes with only 40 samples, their lower F1-scores pull the unweighted average down to 56.63%.
> In SOC production, Weighted F1 (81.24%) is the more meaningful operational metric."

---

### Q4. What is `ColumnTransformer` and why did you serialize it inside the `joblib` pipeline alongside the classifier?
**Examiner's Intent:** To test your ML engineering and production deployment hygiene.

**Your Answer:**
> "A common beginner mistake is to preprocess features outside the model and save only the classifier. That causes **training-serving skew**, where production inference fails if features aren't scaled identically to training data.
> We constructed a single `sklearn.pipeline.Pipeline`:
> 1. `ColumnTransformer` applies `StandardScaler` to 39 numerical features (e.g., `sbytes`, `sttl`, `sload`) and `OneHotEncoder(handle_unknown='ignore')` to 3 categorical features (`proto`, `service`, `state`).
> 2. The output feeds directly into `RandomForestClassifier`.
> 3. We serialized the **entire pipeline** into `veritrace_model.joblib`.
> When the FastAPI backend receives raw JSON traffic at `/api/ml/predict`, it passes the raw dictionary into `pipeline.predict()`. The pipeline automatically handles scaling and encoding in memory with the exact parameters fitted during training."

---

### Q5. Can your model directly detect Ransomware encrypting files on a victim's PC?
**Examiner's Intent:** To test if you understand the boundary between Network Telemetry (NIDS) and Host Telemetry (EDR).

**Your Answer:**
> "It is crucial to clarify the architectural scope:
> - **Our Random Forest model is a Network Intrusion Detection model (NIDS)** trained on packet flow telemetry (UNSW-NB15). It detects the network behaviors associated with attack propagation, such as *Exploits* (initial access), *Reconnaissance* (network port scanning), *DoS* (denial of service), and *Lateral Movement* (Worms).
> - **Host-level file encryption** (e.g., WannaCry encrypting local disk drives) is host-level activity detected by Endpoint Detection and Response (EDR) agents.
> - In VeriTrace, ransomware is managed at the **Incident Command system level**: the incident console provides pre-configured playbooks for ransomware containment, regulatory countdown clocks (CERT-In / RBI 6-hour deadlines), and evidence logging, while the ML model analyzes incoming network packet telemetry."

---

## SECTION 2: SYSTEM ARCHITECTURE & CYBERSECURITY FRAMEWORKS

### Q6. Walk me through the NIST SP 800-61r2 incident response lifecycle and how VeriTrace implements it.
**Examiner's Intent:** To verify whether your cybersecurity workflow follows accredited standards.

**Your Answer:**
> "NIST Special Publication 800-61 Revision 2 defines the gold standard for Computer Security Incident Handling across four core phases:
> 1. **Preparation:** Setting up tools, communication channels, and baselines. VeriTrace provides pre-configured runbooks and an active threat intelligence dashboard.
> 2. **Detection & Analysis:** Identifying unauthorized events. VeriTrace's AI Threat Analysis engine accepts packet features, performs real-time multiclass classification, outputs confidence probabilities, and maps to MITRE ATT&CK tactics.
> 3. **Containment, Eradication & Recovery:** Isolating affected subnets, revoking credentials, and patching vulnerabilities. VeriTrace includes interactive checklist playbooks with status tracking (Pending $\rightarrow$ In Progress $\rightarrow$ Completed).
> 4. **Post-Incident Activity:** Documenting findings and audit defense. VeriTrace calculates compliance metrics and compiles executive forensic reports with SHA-256 chain verification."

---

### Q7. What are the regulatory reporting deadlines enforced in VeriTrace, and why are they critical?
**Examiner's Intent:** To assess your domain knowledge of financial compliance laws.

**Your Answer:**
> "VeriTrace specifically addresses the compliance mandates governing financial institutions and critical data handlers:
> 1. **CERT-In 6-Hour Rule:** Under the April 2022 cybersecurity directions issued by the Indian Computer Emergency Response Team, cyber incidents (including unauthorized access, ransomware, and denial of service) must be formally reported within 6 hours.
> 2. **RBI Cyber Security Framework:** The Reserve Bank of India mandates that banks report any unusual cyber activity or breach to the Cyber Security and IT Examination (CSITE) cell within 2 to 6 hours.
> 3. **GDPR Article 33:** Involves personal data breaches, requiring notification to the Data Protection Authority within 72 hours.
> In our UI, live JavaScript countdown clocks actively monitor these thresholds so the incident commander never violates statutory reporting windows."

---

### Q8. How does the SHA-256 evidence chain of custody work? How is it different from a Blockchain?
**Examiner's Intent:** To test cryptographic understanding and prevent buzzword exaggeration.

**Your Answer:**
> "Our evidence chain implements a **cryptographic hash chain**, the core mathematical primitive behind Merkle trees and blockchains, but tailored for high-speed local enterprise auditability:
> 1. Each evidence log entry contains:
>    $$\text{Hash}_i = \text{SHA256}(\text{Index}_i + \text{Timestamp}_i + \text{Description}_i + \text{Hash}_{i-1})$$
> 2. The first entry has $\text{Hash}_0$ computed against a fixed `previous_hash = "GENESIS"`.
> 3. If an attacker tampers with an existing log record in the database, its recalculated hash changes. Because every subsequent block includes the previous block's hash, the entire chain after that point breaks.
> 4. **Difference from Blockchain:** A blockchain includes decentralized peer-to-peer consensus (Proof of Work / Proof of Stake) and distributed gossip protocols across multiple nodes. VeriTrace uses a centralized, tamper-evident cryptographic ledger, which avoids mining energy and consensus overhead while guaranteeing mathematical non-repudiation."

---

## SECTION 3: BACKEND, APIS & FULL-STACK INTEGRATION

### Q9. How did you optimize the FastAPI backend so that model inference does not reload the 158MB joblib file on every HTTP request?
**Examiner's Intent:** To check if you understand memory management and web server lifecycles.

**Your Answer:**
> "Loading a 158MB model from disk into RAM takes approximately 1.5 seconds. If performed inside the request handler, every API call would suffer unacceptable latency and memory leaks.
> To prevent this, we used FastAPI's modern **`lifespan` context manager**:
> ```python
> @asynccontextmanager
> async def lifespan(app: FastAPI):
>     # Load model into RAM once during server startup
>     ml_service.load_model()
>     yield
>     # Clean up resources on shutdown
> ```
> The loaded model is held in memory as a singleton in `ml_service`. When `POST /api/ml/predict` receives a request, it calls the already-in-memory pipeline, completing inference in under **10 milliseconds**."

---

### Q10. What happens if a client sends invalid or missing data to `POST /api/ml/predict`?
**Examiner's Intent:** To verify schema validation and defensive programming.

**Your Answer:**
> "We implement strict schema validation using **Pydantic v2**:
> 1. All 42 required network parameters are declared with explicit data types in `TrafficPredictionRequest`.
> 2. If a client omits a required field or submits an invalid string instead of a float, FastAPI automatically rejects the request with an **HTTP 422 Unprocessable Entity** error, returning a detailed JSON error payload describing the exact invalid field.
> 3. The server never crashes or enters an unhandled 500 exception state. We verified this behavior in our automated test suite (`backend/test_phase4.py`)."

---

### Q11. How does the frontend handle backend failures or network disconnects?
**Examiner's Intent:** To evaluate graceful degradation and frontend resilience.

**Your Answer:**
> "The frontend implements robust error boundaries:
> 1. On page load, `checkModelStatus()` sends a `GET /api/ml/status` request. If the backend is running, the UI updates the status badge to a glowing green **'READY'**.
> 2. If the backend is unreachable, the badge updates to an amber/red **'OFFLINE'** state, and the UI displays an alert guiding the user to start the FastAPI server.
> 3. In the AI Threat Analysis tab, if an API call fails, the UI displays an inline error message without breaking the navigation or freezing the incident command center."

---

## SECTION 4: TESTING & AUDIT DEFENSE

### Q12. How did you verify and validate that your system works end-to-end?
**Examiner's Intent:** To see if you tested your project systematically or just clicked around randomly.

**Your Answer:**
> "We implemented a 4-tier verification methodology:
> 1. **Unit Testing (`backend/test_backend.py`):** Verified database tables, CRUD operations for incidents, evidence logging, and NIST playbook advancement.
> 2. **ML Endpoint Testing (`backend/test_phase4.py`):** Verified HTTP 200 responses, prediction schema adherence, HTTP 422 error rejection, and metrics verification against `metrics.json`.
> 3. **Integration Testing (`backend/test_frontend_integration.py`):** Verified static file delivery (`/app`, `favicon.svg`), CORS headers, and browser fetch compatibility.
> 4. **Comprehensive 51-Point Final Audit (`final_audit.py`):** An automated audit script checking dataset records (175,341 rows), model parameters (42 features), real predictions across 4 attack categories, cryptographic chain tampering detection, and API latency.
> **All 51 verification checks passed with 100% compliance.**"

---

## QUICK SUMMARY CHEAT SHEET (KEEP IN MIND DURING DEFENSE)

| Topic | Key Number / Term to Mention |
|---|---|
| **Dataset** | UNSW-NB15, 175,341 records, 42 features, 0 missing values |
| **Algorithm** | Random Forest Classifier (100 estimators, max depth 20) |
| **Pipeline** | `ColumnTransformer` (StandardScaler + OneHotEncoder) |
| **Overall Accuracy** | **82.87%** (on 35,069 holdout test records) |
| **Weighted F1** | **81.24%** (reflects real operational packet distribution) |
| **Macro F1** | **56.63%** (unweighted penalty due to extreme class imbalance in Worms/Backdoor) |
| **Inference Time** | **< 10 milliseconds** per packet flow |
| **Frameworks** | NIST SP 800-61r2 (4 phases), MITRE ATT&CK (tactics & techniques) |
| **Regulators** | CERT-In (6 hours), RBI (6 hours), GDPR Art. 33 (72 hours) |
| **Cryptography** | SHA-256 recursive evidence chain with tamper detection |
| **Backend** | Python FastAPI, Uvicorn, SQLAlchemy ORM, SQLite (`veritrace.db`) |
| **Frontend** | Vanilla JavaScript, HTML5, CSS3, Responsive Multi-Tab Console |
