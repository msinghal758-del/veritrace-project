# VERITRACE — PROJECT DEMONSTRATION VIDEO SCRIPT & STORYBOARD
## Step-by-Step Recording Guide for University Project Evaluation 3

**Target Duration:** 4 to 5 Minutes  
**Recommended Tools:** OBS Studio, Loom, Xbox Game Bar (`Win + G`), or Camtasia.  
**Microphone:** Clear voice, quiet room.  
**Resolution:** 1080p Full Screen (1920x1080).

---

## 🎬 VIDEO STRUCTURE AT A GLANCE

| Scene | Duration | Visual on Screen | Spoken Focus |
|---|---|---|---|
| **Scene 1** | 0:00 – 0:45 | Title Slide / Landing Page | Problem statement, regulatory 6-hour deadlines, financial crisis. |
| **Scene 2** | 0:45 – 1:30 | Terminal / Batch Launcher | Architecture, FastAPI startup, model loading into memory. |
| **Scene 3** | 1:30 – 2:30 | AI Threat Analysis Tab | Live inference on packet presets, probabilities, MITRE mapping. |
| **Scene 4** | 2:30 – 3:20 | Evidence Chain & Ledger | SHA-256 tamper-evident chain of custody, attaching AI findings. |
| **Scene 5** | 3:20 – 4:10 | ML Performance Dashboard | 82.87% Accuracy, 81.24% Weighted F1, confusion matrix analysis. |
| **Scene 6** | 4:10 – 4:45 | Incident Console & Export | NIST workflow, executive report export, final summary. |

---

## 🎙️ SCENE-BY-SCENE SCRIPT & ACTION STEPS

### SCENE 1: INTRODUCTION & THE CYBER CRISIS (0:00 – 0:45)
**Screen Setup:** Open browser at `http://127.0.0.1:8000/app` showing the VeriTrace Hero section.

> **What to Say:**  
> *"Hello everyone and respected evaluators. Today, I am demonstrating **VeriTrace**, an AI-powered Cyber Incident Response and Digital Forensics platform built for banking and regulated financial infrastructure.*  
>  
> *In cybersecurity, when a breach occurs, the clock starts immediately. The Reserve Bank of India and CERT-In strictly mandate that cyber incidents must be reported within **6 hours**, while GDPR enforces a **72-hour** notification rule. Today's Security Operations Centers suffer from alert fatigue and manual packet analysis delays.*  
>  
> *VeriTrace solves this by combining real-time Machine Learning threat classification, NIST SP 800-61r2 incident workflows, and an immutable SHA-256 digital evidence chain of custody."*

---

### SCENE 2: SYSTEM ARCHITECTURE & ONE-CLICK STARTUP (0:45 – 1:30)
**Screen Setup:** Switch to Windows terminal or show `start_veritrace.bat` executing, then open Swagger UI at `http://127.0.0.1:8000/docs`.

**Action:**
1. Show the terminal running Uvicorn on port 8000.
2. Quickly show the Swagger docs tab showing `/api/ml/predict`, `/api/ml/metrics`, `/api/incidents`.

> **What to Say:**  
> *"Under the hood, VeriTrace is powered by a high-performance **Python FastAPI** backend backed by an SQLite database.  
>  
> Rather than reloading our 158-megabyte trained machine learning model on every HTTP request, our server uses FastAPI's lifespan manager to load the model into memory once at startup, allowing sub-10 millisecond inference times.  
>  
> The system exposes clean, documented RESTful endpoints for model status, real-time prediction, metrics reporting, and cryptographic incident ledger management."*

---

### SCENE 3: LIVE AI THREAT ANALYSIS & MITRE MAPPING (1:30 – 2:30)
**Screen Setup:** Switch back to `http://127.0.0.1:8000/app` and click **"Open Incident Console"**, then click the **"AI Threat Analysis"** tab.

**Action:**
1. Point to the glowing green **"MODEL STATUS: READY"** badge.
2. Click the preset button: **"Web Exploit Payload"**.
3. Watch the form fields populate (e.g. `dur`, `sbytes`, `sttl`, `proto=tcp`, `service=http`).
4. Click **"Run AI Analysis"**.
5. Show the results panel animating into view.
6. Click another preset: **"SYN Flood / DoS"** and run analysis again.

> **What to Say:**  
> *"Now let's enter the Incident Console. Notice the green status badge confirming our Scikit-learn model is ready.  
>  
> In the AI Threat Analysis tab, SOC analysts can evaluate incoming network packet flows. Let's load a real packet flow preset — for example, a **Web Exploit Payload**.  
>  
> Clicking 'Run AI Analysis' sends 42 network flow parameters to our FastAPI backend. In just 7 milliseconds, our trained Random Forest model analyzes the telemetry.  
>  
> It classifies this packet as an **Exploits attack** with an 88.5% confidence score. Below, it provides the full probability distribution across all 10 classes, and dynamically maps the threat to **MITRE ATT&CK Technique T1190: Exploit Public-Facing Application** under the **Initial Access** tactic, automatically rating the severity as HIGH."*

---

### SCENE 4: CRYPTOGRAPHIC EVIDENCE CHAIN OF CUSTODY (2:30 – 3:20)
**Screen Setup:** In the prediction result card, highlight the button **"Attach to Evidence Ledger"**.

**Action:**
1. Click **"Attach to Evidence Ledger"**.
2. A green notification appears: *"AI Prediction attached to incident evidence ledger!"*
3. Click the **"Incident Command"** tab.
4. Scroll down to the **"Evidence Timeline & Chain of Custody"** section.
5. Highlight the newly added block containing the AI classification and its generated **SHA-256 hash**.
6. Point out the previous hash reference.

> **What to Say:**  
> *"In a regulated banking environment, an analytical prediction is useless unless it is legally admissible. VeriTrace allows the analyst to attach this AI finding directly to the forensic chain of custody with a single click.  
>  
> Let's switch to the Incident Command tab. In the Evidence Timeline, you can see our new entry.  
>  
> Each evidence log entry is cryptographically linked to the previous block using recursive SHA-256 hashing. If an attacker or insider alters even one byte in the database, the hash chain breaks instantly, ensuring complete non-repudiation during regulatory audits."*

---

### SCENE 5: ML PERFORMANCE DASHBOARD & METRICS TRANSPARENCY (3:20 – 4:10)
**Screen Setup:** Click the **"ML Model Performance"** tab.

**Action:**
1. Highlight the metric cards: Overall Accuracy (`82.87%`), Weighted F1 (`81.24%`), Macro F1 (`56.63%`).
2. Scroll down to the **Confusion Matrix** grid.
3. Hover over the diagonal elements (Normal: 10,448 correct; Generic: 7,707 correct).
4. Point out the Per-Class Metrics table.

> **What to Say:**  
> *"Transparency is paramount in AI systems. The ML Model Performance tab displays genuine evaluation metrics fetched directly from our backend API — nothing is hardcoded or fabricated.  
>  
> Our Random Forest model was trained on the official **UNSW-NB15** dataset containing **175,341 network records**, evaluated on a strict 20% holdout test partition of 35,069 samples.  
>  
> We achieved **82.87% Overall Accuracy** and **81.24% Weighted F1-score**.  
>  
> You can examine our interactive confusion matrix and per-class breakdown. Notice that while major classes like Normal and Generic achieve F1-scores between 87% and 97%, rare classes like Worms have fewer samples, which transparently explains our Macro F1 of 56.63%."*

---

### SCENE 6: NIST PLAYBOOK, REPORT GENERATION & WRAP-UP (4:10 – 4:45)
**Screen Setup:** Switch back to the **Incident Command** tab.

**Action:**
1. Show the active regulatory countdown clocks: CERT-In (6h) and GDPR (72h).
2. Check off a playbook task under Containment.
3. Click **"Download Incident Report"** to show the generated audit summary.

> **What to Say:**  
> *"Finally, the Incident Command tab guides the security team through the 4 phases of NIST SP 800-61r2, keeping real-time track of our statutory 6-hour CERT-In countdown.  
>  
> Once containment is achieved, the analyst can generate an executive incident report ready for submission to regulatory authorities and law enforcement.  
>  
> In summary, VeriTrace successfully bridges machine learning, digital forensics, and compliance into a unified, audit-ready platform. Thank you!"*

---

## 💡 PRO TIPS FOR RECORDING

1. **Keep Browser Zoom at 90% or 100%:** This ensures all three tabs, graphs, and metric cards fit comfortably within the 1080p viewport without excessive vertical scrolling.
2. **Clear Browser Cache / Reload:** Start the recording with a clean incident loaded so the counters and timers are ticking smoothly.
3. **Pacing:** Speak at a steady, confident pace. Don't rush through the metrics; professors value the technical explanation of the Weighted F1 vs. Macro F1 distinction.
4. **Backup Plan:** If presenting live in front of the evaluator, practice the preset clicks twice beforehand!
