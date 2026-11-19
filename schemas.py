from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


# --- Dataset Schemas ---

class DatasetStatsResponse(BaseModel):
    dataset_name: str
    source: str
    total_records: int
    total_features: int
    columns: List[str]
    attack_categories: Dict[str, int]
    top_protocols: Dict[str, int]
    top_services: Dict[str, int]
    normal_count: int
    attack_count: int
    imported_at: str


class DatasetRecordResponse(BaseModel):
    id: int
    dur: float
    proto: str
    service: str
    state: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    rate: float
    sttl: int
    dttl: int
    attack_cat: str
    label: int


class DatasetRecordsListResponse(BaseModel):
    total_available_in_db: int
    limit: int
    offset: int
    filter_category: Optional[str] = None
    records: List[Dict[str, Any]]


# --- Incident Schemas ---

class PlaybookStepSchema(BaseModel):
    id: str
    phase: int
    text: str
    src: str = ""
    atk: str = ""
    done: bool = False
    by: Optional[str] = None

    class Config:
        from_attributes = True


class EvidenceLogSchema(BaseModel):
    id: int
    ts: int
    actor: str
    action: str
    extra: str = ""
    prev_hash: str
    current_hash: str

    class Config:
        from_attributes = True


class IncidentCreate(BaseModel):
    key: str  # ransomware, phishing, etc.
    title: str
    discovered: int  # epoch ms
    pii: bool = False
    eu: bool = False
    notes: Optional[str] = ""
    owner: Optional[str] = "SOC Analyst"
    attack_category: Optional[str] = ""
    severity: Optional[str] = "Critical"


class IncidentResponse(BaseModel):
    id: str
    key: str
    title: str
    discovered: int
    pii: bool
    eu: bool
    notes: str
    attack_category: str
    severity: str
    view_phase: int
    owner: str
    created_at: int
    steps: List[PlaybookStepSchema] = []
    evidence_logs: List[EvidenceLogSchema] = []

    class Config:
        from_attributes = True


class EvidenceCreate(BaseModel):
    actor: str
    action: str
    extra: Optional[str] = ""
    file_name: Optional[str] = None
    file_sha256: Optional[str] = None


class StepToggle(BaseModel):
    done: bool
    by: Optional[str] = None


# --- Machine Learning Schemas ---

class TrafficPredictionRequest(BaseModel):
    dur: Optional[float] = Field(default=0.0, description="Connection duration in seconds")
    proto: Optional[str] = Field(default="tcp", description="Protocol, e.g. tcp, udp, icmp")
    service: Optional[str] = Field(default="-", description="Service, e.g. http, ftp, dns")
    state: Optional[str] = Field(default="FIN", description="Connection state, e.g. FIN, CON, INT")
    spkts: Optional[int] = Field(default=2, description="Source packet count")
    dpkts: Optional[int] = Field(default=0, description="Destination packet count")
    sbytes: Optional[int] = Field(default=200, description="Source bytes")
    dbytes: Optional[int] = Field(default=0, description="Destination bytes")
    rate: Optional[float] = Field(default=10.0, description="Packet rate")
    sttl: Optional[int] = Field(default=62, description="Source TTL")
    dttl: Optional[int] = Field(default=0, description="Destination TTL")

    class Config:
        extra = "allow"


class PredictionResponse(BaseModel):
    predicted_attack_category: str
    is_attack: bool
    confidence: float
    confidence_percentage: str
    severity: str
    mitre_attack: str
    class_probabilities: Dict[str, float]
    inference_time_ms: float
    features_evaluated: int


class MetricsSummary(BaseModel):
    accuracy: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    macro_precision: float
    macro_recall: float
    macro_f1: float


class MetricsResponse(BaseModel):
    dataset: str
    model_type: str
    total_records: int
    train_records: int
    test_records: int
    summary: MetricsSummary
    per_class_report: Dict[str, Any]
    confusion_matrix: Dict[str, Any]
    parameters: Dict[str, Any]
    features: Dict[str, Any]
    trained_at: str
    training_duration_seconds: float
    evaluation_duration_seconds: float

