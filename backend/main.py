"""
Security Event Deep Clustering API
FastAPI backend for processing and clustering security events
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder

from pydantic import BaseModel, Field
from typing import Optional
import csv
import json
import numpy as np
import torch
from enum import Enum
import uuid
import asyncio
from datetime import datetime
from collections import Counter, defaultdict

from event_parser import EventParser, SecurityEvent
from deep_clustering import (
    DeepEmbeddedClustering,
    ImprovedDEC,
    VaDE,
    ContrastiveDeepClustering
)
from trainer import DeepClusteringTrainer, TrainingConfig, ModelType, ClusteringMetrics
from cluster_analyzer import ClusterAnalyzer, analyze_clusters_from_results, ClusterProfile
from security_insights import SecurityInsightsEngine, SecurityInsight, ClusterCorrelation

from multiprocessing import Manager, Process

app = FastAPI(
    title="Security Event Deep Clustering API",
    description="Deep learning-based clustering for security event analysis",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# wrapper app
root_app = FastAPI()

# mount original app under /api
root_app.mount("/api", app)

# Global state for training jobs
#manager = Manager()

training_jobs = {} # manager.dict()
trained_models = {}
parser = EventParser()
analyzer = ClusterAnalyzer(parser)
insights_engine = SecurityInsightsEngine()


# Pydantic models for API
class ModelTypeEnum(str, Enum):
    DEC = "dec"
    IDEC = "idec"
    VADE = "vade"
    CONTRASTIVE = "contrastive"


class TrainingRequest(BaseModel):
    events: list[str] = Field(..., description="List of raw security event strings")
    model_type: ModelTypeEnum = Field(default=ModelTypeEnum.IDEC, description="Deep clustering model type")
    n_clusters: int = Field(default=10, ge=2, le=100, description="Number of clusters")
    latent_dim: int = Field(default=32, ge=8, le=256, description="Latent space dimension")
    hidden_dims: list[int] = Field(default=[256, 128, 64], description="Hidden layer dimensions")
    pretrain_epochs: int = Field(default=30, ge=5, le=200, description="Pretraining epochs")
    finetune_epochs: int = Field(default=50, ge=10, le=300, description="Fine-tuning epochs")
    batch_size: int = Field(default=128, ge=16, le=1024, description="Batch size")
    learning_rate: float = Field(default=1e-3, gt=0, le=0.1, description="Learning rate")


class PredictRequest(BaseModel):
    job_id: str = Field(..., description="Training job ID")
    events: list[str] = Field(..., description="Events to predict clusters for")


class AnalyzeRequest(BaseModel):
    job_id: str = Field(..., description="Training job ID")
    events: list[str] = Field(..., description="Events to analyze")


class TrainingProgress(BaseModel):
    job_id: str
    status: str
    progress: float  # Overall progress 0-100
    stage: str = "initializing"  # "initializing" | "pretraining" | "initialization" | "fine-tuning" | "postprocessing"
    stage_progress: float = 0.0  # Progress within current stage 0-100
    current_epoch: int
    total_epochs: int
    stage_epoch: int = 0  # Epoch within current stage
    stage_total_epochs: int = 0  # Total epochs for current stage
    current_loss: float
    metrics: Optional[dict] = None
    message: str = ""
    stages_completed: list[str] = []  # e.g., ["pretraining"]


class ClusterResult(BaseModel):
    cluster_id: int
    size: int
    threat_level: str
    primary_subsystems: list[str]
    primary_actions: list[str]
    threat_indicators: list[str]
    recommended_actions: list[str]
    top_source_ips: list[tuple]
    top_dest_ports: list[tuple]
    representative_events: list[dict]


class AnalysisResponse(BaseModel):
    total_events: int
    n_clusters: int
    clusters: list[ClusterResult]
    summary: dict
    intrinsic_metrics: Optional[dict] = None
    latent_visualization: Optional[dict] = None


# Helper functions
def parse_events_to_features(raw_events: list[str]) -> tuple[list[SecurityEvent], np.ndarray]:
    """Parse raw events and convert to feature matrix"""
    events = parser.parse_events(raw_events)
    features = np.array([parser.event_to_features(e) for e in events], dtype=np.float32)
    
    # Normalize features
    mean = features.mean(axis=0)
    std = features.std(axis=0) + 1e-8
    features = (features - mean) / std
    
    return events, features



async def run_training(
    job_id: str,
    raw_events: list[str],
    config: TrainingConfig,
    model_type: ModelType
):
    """Background task for training deep clustering model - includes event parsing"""
    try:
        # Parse events in background so endpoint response isn't delayed
        training_jobs[job_id]["status"] = "parsing"
        training_jobs[job_id]["message"] = "Parsing security events..."
        await asyncio.sleep(0.5)  # yield control to allow frontend polling
        try:
            events, features = parse_events_to_features(raw_events)
        except Exception as e:
            training_jobs[job_id]["status"] = "failed"
            training_jobs[job_id]["message"] = f"Error parsing events: {str(e)}"
            return
        

        training_jobs[job_id]["n_events"] = len(events)
        training_jobs[job_id]["status"] = "training"
        training_jobs[job_id]["message"] = "Initializing trainer..."
        
        await asyncio.sleep(0.5)  # yield control

        trainer = DeepClusteringTrainer(
            input_dim=features.shape[1],
            model_type=model_type,
            config=config
        )
        
        # Pretraining
        training_jobs[job_id]["stage"] = "pretraining"
        training_jobs[job_id]["message"] = "Pretraining autoencoder..."
        training_jobs[job_id]["stage_total_epochs"] = config.pretrain_epochs
        total_pretrain = config.pretrain_epochs

        await asyncio.sleep(0.5)  # yield control
        
        async def pretrain_callback(epoch, loss):
            training_jobs[job_id]["current_epoch"] = epoch + 1
            training_jobs[job_id]["stage_epoch"] = epoch + 1
            training_jobs[job_id]["current_loss"] = loss
            progress_pct = (epoch + 1) / total_pretrain
            training_jobs[job_id]["stage_progress"] = progress_pct * 100
            training_jobs[job_id]["progress"] = progress_pct * 50  # Pretraining is ~50% of total
            await asyncio.sleep(0.05)  # yield control after each epoch
        
        await trainer.pretrain(features, pretrain_callback)
        training_jobs[job_id]["stages_completed"].append("pretraining")
        
        # Initialize clusters
        training_jobs[job_id]["stage"] = "initialization"
        training_jobs[job_id]["message"] = "Initializing cluster centers..."
        training_jobs[job_id]["stage_total_epochs"] = 0  # Initialization is not epoch-based
        training_jobs[job_id]["stage_progress"] = 0
        training_jobs[job_id]["stage_epoch"] = 0
        training_jobs[job_id]["progress"] = 50  # Show 50% progress during initialization
        await asyncio.sleep(0.1)  # yield control
        
        async def init_callback(progress_pct):
            training_jobs[job_id]["stage_progress"] = progress_pct
            # Overall progress: 50% + 50% of init stage (scales 50-75% during init)
            training_jobs[job_id]["progress"] = 50 + (progress_pct * 0.5)
            await asyncio.sleep(0.05)  # yield control during initialization
        
        await trainer.initialize_clusters(features, progress_callback=init_callback)
        
        training_jobs[job_id]["stages_completed"].append("initialization")
        training_jobs[job_id]["stage_progress"] = 100
        training_jobs[job_id]["progress"] = 75  # At 75% after initialization
        
        # Fine-tuning
        training_jobs[job_id]["stage"] = "fine-tuning"
        training_jobs[job_id]["message"] = "Fine-tuning with clustering objective..."
        training_jobs[job_id]["stage_total_epochs"] = config.finetune_epochs
        training_jobs[job_id]["stage_epoch"] = 0
        training_jobs[job_id]["stage_progress"] = 0
        
        await asyncio.sleep(0.1)  # yield control
        
        async def finetune_callback(epoch, metrics):
            training_jobs[job_id]["current_epoch"] = total_pretrain + epoch + 1
            training_jobs[job_id]["stage_epoch"] = epoch + 1
            training_jobs[job_id]["metrics"] = metrics
            progress_pct = (epoch + 1) / config.finetune_epochs
            training_jobs[job_id]["stage_progress"] = progress_pct * 100
            training_jobs[job_id]["progress"] = 50 + (progress_pct * 50)  # Fine-tuning is the other ~50%
            await asyncio.sleep(0.05)  # yield control after each epoch
        
        await trainer.finetune(features, progress_callback=finetune_callback)
        
        # Refinement stage
        training_jobs[job_id]["stage"] = "postprocessing"
        training_jobs[job_id]["message"] = "Refining cluster assignments..."
        training_jobs[job_id]["stage_total_epochs"] = 0
        training_jobs[job_id]["stage_epoch"] = 0
        training_jobs[job_id]["stage_progress"] = 0
        training_jobs[job_id]["progress"] = 95
        await asyncio.sleep(0.05)

        async def refine_progress_callback(progress_pct: float):
            training_jobs[job_id]["stage_progress"] = progress_pct
            # Postprocessing occupies the final 5% (95 -> 100)
            training_jobs[job_id]["progress"] = 95 + (progress_pct * 0.05)
            print(f"[refinement] job={job_id} progress={progress_pct:.1f}% overall={training_jobs[job_id]['progress']:.2f}%")
            await asyncio.sleep(0.05)

        # Get final results
        labels = trainer.predict(features)
        latent = trainer.get_latent_representations(features)
        labels, refinement_info = await trainer.refine_cluster_assignments(
            latent,
            labels,
            progress_callback=refine_progress_callback
        )
        probs = trainer.get_cluster_probabilities(features)
        
        # Analyze clusters
        profiles, summary = analyze_clusters_from_results(events, labels, latent)
        
        # Store results
        trained_models[job_id] = {
            "trainer": trainer,
            "events": events,
            "features": features,
            "labels": labels,
            "latent": latent,
            "probs": probs,
            "refinement_info": refinement_info,
            "profiles": profiles,
            "summary": summary,
            "feature_mean": features.mean(axis=0),
            "feature_std": features.std(axis=0) + 1e-8
        }
        
        training_jobs[job_id]["status"] = "completed"
        training_jobs[job_id]["progress"] = 100
        training_jobs[job_id]["stage_progress"] = 100
        training_jobs[job_id]["message"] = "Training completed successfully"
        training_jobs[job_id]["metrics"] = ClusteringMetrics.compute_all(labels, features=latent)
        training_jobs[job_id]["refinement"] = refinement_info
        
    except Exception as e:
        training_jobs[job_id]["status"] = "failed"
        training_jobs[job_id]["message"] = str(e)
        raise

async def delayed_training(job_id, events, config, model_type):
    await asyncio.sleep(2)  # wait before starting
    await run_training(job_id, events, config, model_type)

# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "cuda_available": torch.cuda.is_available(),
        "device": "cuda" if torch.cuda.is_available() else "cpu"
    }


@app.get("/models")
async def list_models():
    """List available deep clustering models"""
    return {
        "models": [
            {
                "id": "dec",
                "name": "Deep Embedded Clustering (DEC)",
                "description": "Uses KL divergence to iteratively refine cluster assignments"
            },
            {
                "id": "idec",
                "name": "Improved DEC (IDEC)",
                "description": "DEC with reconstruction loss for better representation learning"
            },
            {
                "id": "vade",
                "name": "Variational Deep Embedding (VaDE)",
                "description": "Combines VAE with GMM for probabilistic clustering"
            },
            {
                "id": "contrastive",
                "name": "Contrastive Deep Clustering",
                "description": "Uses contrastive learning for robust representations"
            }
        ]
    }


@app.post("/train")
async def start_training(request: TrainingRequest, background_tasks: BackgroundTasks):
    """Start deep clustering training job"""
    
    if len(request.events) < 100:
        raise HTTPException(
            status_code=400,
            detail="At least 100 events required for deep clustering"
        )
    
    if request.n_clusters > len(request.events) // 10:
        raise HTTPException(
            status_code=400,
            detail="Too many clusters for the number of events"
        )
    
    # Create training config
    config = TrainingConfig(
        hidden_dims=request.hidden_dims,
        latent_dim=request.latent_dim,
        n_clusters=request.n_clusters,
        pretrain_epochs=request.pretrain_epochs,
        finetune_epochs=request.finetune_epochs,
        pretrain_batch_size=request.batch_size,
        finetune_batch_size=request.batch_size,
        pretrain_lr=request.learning_rate,
        finetune_lr=request.learning_rate / 10
    )
    
    # Create job - store raw events, parsing happens in background
    job_id = str(uuid.uuid4())
    model_type = ModelType(request.model_type.value)
    
    training_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "stage": "initializing",
        "stage_progress": 0,
        "current_epoch": 0,
        "total_epochs": config.pretrain_epochs + config.finetune_epochs,
        "stage_epoch": 0,
        "stage_total_epochs": 0,
        "current_loss": 0.0,
        "metrics": None,
        "message": "Queued - waiting to parse events...",
        "stages_completed": [],
        "model_type": request.model_type.value,
        "n_events": len(request.events),  # Raw event count
        "n_clusters": request.n_clusters,
        "created_at": datetime.now().isoformat()
    }
    
    # Start training in background (response returned immediately)
    background_tasks.add_task(
        delayed_training, #run_training,
        job_id,
        request.events,  # Pass raw events, not parsed
        config,
        model_type
    )

    # p = Process(
    #     target=run_training,
    #     args=(job_id, request.events, config, model_type)
    # )
    # p.start()

    print(f"Started training job {job_id} with model {model_type.value}")
    return {"job_id": job_id, "message": "Training started"}


@app.get("/train/{job_id}")
async def get_training_status(job_id: str):
    """Get training job status"""
    if job_id not in training_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # return training_jobs[job_id]
    return jsonable_encoder(
        training_jobs[job_id],
        custom_encoder={np.generic: lambda x: x.item()}
    )


@app.get("/results/{job_id}")
async def get_results(job_id: str):
    """Get clustering results for a completed job"""
    if job_id not in trained_models:
        if job_id in training_jobs:
            status = training_jobs[job_id]["status"]
            if status != "completed":
                raise HTTPException(
                    status_code=400,
                    detail=f"Training not completed. Status: {status}"
                )
        raise HTTPException(status_code=404, detail="Results not found")
    
    model_data = trained_models[job_id]
    profiles = model_data["profiles"]
    summary = model_data["summary"]
    latent = model_data["latent"]
    labels = model_data["labels"]
    intrinsic_metrics = ClusteringMetrics.compute_all(labels, features=latent)
    
    # Prepare cluster results
    clusters = []
    for profile in profiles:
        clusters.append(ClusterResult(
            cluster_id=profile.cluster_id,
            size=profile.size,
            threat_level=profile.threat_level,
            primary_subsystems=profile.primary_subsystems,
            primary_actions=profile.primary_actions,
            threat_indicators=profile.threat_indicators,
            recommended_actions=profile.recommended_actions,
            top_source_ips=profile.top_source_ips,
            top_dest_ports=profile.top_dest_ports,
            representative_events=profile.representative_events
        ))
    
    # Prepare 2D visualization data (using first 2 PCA components)
    from sklearn.decomposition import PCA
    pca = PCA(n_components=2)
    latent_2d = pca.fit_transform(latent)
    
    visualization = {
        "points": [
            {"x": float(latent_2d[i, 0]), "y": float(latent_2d[i, 1]), "cluster": int(labels[i])}
            for i in range(len(labels))
        ],
        "explained_variance": pca.explained_variance_ratio_.tolist()
    }
    
    return AnalysisResponse(
        total_events=len(labels),
        n_clusters=len(profiles),
        clusters=clusters,
        summary=summary,
        intrinsic_metrics=intrinsic_metrics,
        latent_visualization=visualization
    )


@app.post("/predict")
async def predict_clusters(request: PredictRequest):
    """Predict cluster assignments for new events"""
    if request.job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[request.job_id]
    trainer = model_data["trainer"]
    
    # Parse and normalize new events
    events, features = parse_events_to_features(request.events)
    
    # Predict
    labels = trainer.predict(features)
    probs = trainer.get_cluster_probabilities(features)
    latent = trainer.get_latent_representations(features)
    
    results = []
    for i, (event, label, prob) in enumerate(zip(events, labels, probs)):
        results.append({
            "event_index": i,
            "cluster_id": int(label),
            "confidence": float(prob.max()),
            "probabilities": prob.tolist(),
            "event_summary": {
                "subsystem": event.subsystem,
                "action": event.action,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port
            }
        })
    
    return {"predictions": results}


@app.get("/cluster-events/{job_id}/{cluster_id}")
async def get_cluster_events(job_id: str, cluster_id: int, page: int = 1, limit: int = 30):
    """Get paginated events belonging to a specific cluster"""
    if job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    if page < 1 or limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="Invalid page or limit parameters")
    
    model_data = trained_models[job_id]
    labels = model_data["labels"]
    events = model_data["events"]
    
    # Get indices of events in this cluster
    cluster_indices = [i for i, label in enumerate(labels) if label == cluster_id]
    
    if not cluster_indices:
        raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} has no events")
    
    # Calculate pagination
    total_events = len(cluster_indices)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_indices = cluster_indices[start_idx:end_idx]
    
    # Build event response
    cluster_events = []
    for idx in paginated_indices:
        event = events[idx]
        cluster_events.append({
            "index": idx,
            "timestamp": event.timestamp,
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "dest_port": event.dest_port,
            "subsystem": event.subsystem,
            "action": event.action,
            "severity": event.severity,
            "content": event.content
        })
    
    return {
        "job_id": job_id,
        "cluster_id": cluster_id,
        "total_events": total_events,
        "page": page,
        "limit": limit,
        "total_pages": (total_events + limit - 1) // limit,
        "events": cluster_events
    }


@app.post("/analyze")
async def analyze_events(request: AnalyzeRequest):
    """Analyze events using trained model and return security insights"""
    if request.job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[request.job_id]
    trainer = model_data["trainer"]
    profiles = model_data["profiles"]
    
    # Parse and predict
    events, features = parse_events_to_features(request.events)
    labels = trainer.predict(features)
    
    # Analyze new events
    new_profiles, new_summary = analyze_clusters_from_results(events, labels)
    
    # Match with existing cluster profiles
    cluster_insights = []
    for new_profile in new_profiles:
        existing_profile = next(
            (p for p in profiles if p.cluster_id == new_profile.cluster_id),
            None
        )
        
        cluster_insights.append({
            "cluster_id": new_profile.cluster_id,
            "event_count": new_profile.size,
            "threat_level": new_profile.threat_level,
            "threat_indicators": new_profile.threat_indicators,
            "recommended_actions": new_profile.recommended_actions,
            "matches_known_pattern": existing_profile is not None,
            "known_pattern_info": {
                "threat_level": existing_profile.threat_level if existing_profile else None,
                "primary_subsystems": existing_profile.primary_subsystems if existing_profile else []
            } if existing_profile else None
        })
    
    return {
        "total_events": len(events),
        "clusters_found": len(new_profiles),
        "cluster_insights": cluster_insights,
        "summary": new_summary,
        "high_priority_clusters": [
            c for c in cluster_insights 
            if c["threat_level"] in ["critical", "high"]
        ]
    }


@app.get("/demo")
async def get_demo_events():
    """Get sample security events for demonstration"""
    sample_events = [
        "timestamp=2024-01-15 08:30:00 sourceip=192.168.1.100 destip=10.0.0.50 destport=443 subsys=firewall action=allow proto=HTTPS user=john.doe",
        "timestamp=2024-01-15 08:31:00 sourceip=203.0.113.50 destip=10.0.0.1 destport=22 subsys=ips action=blocked content='SSH brute force attempt detected'",
        "timestamp=2024-01-15 08:32:00 sourceip=192.168.1.150 destip=8.8.8.8 destport=53 subsys=dns action=allow proto=UDP",
        "timestamp=2024-01-15 08:33:00 sourceip=198.51.100.25 destip=10.0.0.80 destport=80 subsys=waf action=blocked content='SQL injection attempt'",
        "timestamp=2024-01-15 08:34:00 sourceip=192.168.1.200 destip=10.0.0.25 destport=25 subsys=mail action=quarantine content='Phishing email detected'",
        "timestamp=2024-01-15 08:35:00 sourceip=172.16.0.50 destip=external destport=443 subsys=vpn action=allow user=remote.user content='VPN tunnel established'",
        "timestamp=2024-01-15 08:36:00 sourceip=10.10.10.10 destip=192.168.1.1 destport=445 subsys=firewall action=denied content='SMB traffic blocked'",
        "timestamp=2024-01-15 08:37:00 sourceip=203.0.113.100 destip=10.0.0.1 destport=3389 subsys=ips severity=high action=blocked content='RDP brute force'",
        "timestamp=2024-01-15 08:38:00 sourceip=192.168.1.50 destip=malware.bad.com destport=80 subsys=webfilter action=blocked content='Malware site blocked'",
        "timestamp=2024-01-15 08:39:00 sourceip=198.51.100.50 destip=10.0.0.100 destport=4444 subsys=ddos severity=critical action=blocked content='DDoS attack mitigated'",
    ]
    
    return {
        "sample_events": sample_events,
        "total_samples": len(sample_events),
        "note": "Use these as template for your security event format"
    }


class FileUploadResponse(BaseModel):
    filename: str
    total_events: int
    events: list[str]
    format_detected: str
    sample_events: list[str]
    errors: list[str] = []


@app.post("/upload")
async def upload_event_log(file: UploadFile = File(...)):
    """
    Upload security event log file for processing
    
    Supports:
    - .txt: One event per line
    - .csv: Each row as an event (automatically formatted)
    - .json: Array of events or JSONL format (one JSON per line)
    
    Returns parsed events ready for training
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Get file extension
    file_ext = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
    errors = []
    events = []
    format_detected = "unknown"
    
    try:
        content = await file.read()
        content_str = content.decode('utf-8')
        
        if file_ext == 'json':
            # Try JSONL format first (one JSON per line)
            format_detected = "jsonl"
            lines = content_str.strip().split('\n')
            event_count = 0
            
            for line in lines:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    # Convert dict to space-separated key=value format
                    event_str = ' '.join([f'{k}={v}' for k, v in obj.items()])
                    events.append(event_str)
                    event_count += 1
                except json.JSONDecodeError:
                    # Fall back to array format
                    format_detected = "json_array"
                    try:
                        data = json.loads(content_str)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    event_str = ' '.join([f'{k}={v}' for k, v in item.items()])
                                    events.append(event_str)
                                elif isinstance(item, str):
                                    events.append(item)
                        break
                    except json.JSONDecodeError as e:
                        errors.append(f"Invalid JSON format: {str(e)}")
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid JSON file: {str(e)}"
                        )
        
        elif file_ext == 'csv':
            format_detected = "csv"
            lines = content_str.strip().split('\n')
            
            if not lines:
                raise HTTPException(status_code=400, detail="CSV file is empty")
            
            reader = list(csv.reader(lines))
            
            # Treat first row as header if it looks like headers
            start_idx = 0
            if len(reader) > 0 and all(cell.lower() in ['timestamp', 'sourceip', 'source_ip', 'destip', 'dest_ip', 'destport', 'dest_port', 'subsys', 'subsystem', 'action', 'severity', 'content', 'event'] for cell in reader[0]):
                headers = reader[0]
                start_idx = 1
            else:
                # Auto-generate headers
                headers = [f'field_{i}' for i in range(len(reader[0])) ] if reader else []
            
            # Convert rows to events
            for row in reader[start_idx:]:
                if not row or all(not cell.strip() for cell in row):
                    continue
                
                event_dict = {}
                for i, cell in enumerate(row):
                    if i < len(headers):
                        event_dict[headers[i]] = cell.strip()
                
                # Convert to space-separated format
                event_str = ' '.join([f'{k}={v}' for k, v in event_dict.items()])
                events.append(event_str)
        
        elif file_ext == 'txt':
            format_detected = "txt"
            lines = content_str.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if line:  # Skip empty lines
                    events.append(line)
        
        else:
            # Try to auto-detect format
            content_str = content_str.strip()
            
            # Try JSON first
            try:
                data = json.loads(content_str)
                format_detected = "json"
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            event_str = ' '.join([f'{k}={v}' for k, v in item.items()])
                            events.append(event_str)
                        else:
                            events.append(str(item))
            except json.JSONDecodeError:
                # Fall back to line-by-line (assume txt format)
                format_detected = "txt"
                lines = content_str.split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        events.append(line)
        
        if not events:
            raise HTTPException(
                status_code=400,
                detail="No valid events found in file"
            )
        
        return FileUploadResponse(
            filename=file.filename,
            total_events=len(events),
            events=events,
            format_detected=format_detected,
            sample_events=events[:5],  # Return first 5 as samples
            errors=errors
        )
    
    except HTTPException:
        raise
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File must be UTF-8 encoded text"
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error processing file: {str(e)}"
        )


@app.delete("/job/{job_id}")
async def delete_job(job_id: str):
    """Delete a training job and its results"""
    deleted = False
    
    if job_id in training_jobs:
        del training_jobs[job_id]
        deleted = True
    
    if job_id in trained_models:
        del trained_models[job_id]
        deleted = True
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {"message": "Job deleted successfully"}


# ==================== SECURITY INSIGHTS ENDPOINTS ====================

class InsightResponse(BaseModel):
    insight_id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: float
    event_count: int
    sample_events: list[dict]
    affected_subsystems: list[str]
    source_ips: list[str]
    target_assets: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    immediate_actions: list[str]
    long_term_actions: list[str]
    ioc_indicators: list[dict]


class CorrelationResponse(BaseModel):
    cluster_a: int
    cluster_b: int
    correlation_type: str
    correlation_strength: float
    shared_indicators: list[str]
    description: str


class FullInsightsResponse(BaseModel):
    job_id: str
    total_events: int
    total_clusters: int
    insights: list[InsightResponse]
    correlations: list[CorrelationResponse]
    executive_summary: dict
    threat_landscape: dict


@app.get("/insights/{job_id}")
async def get_security_insights(job_id: str):
    """
    Get comprehensive security insights for a completed clustering job.
    This extracts rich, actionable intelligence including:
    - Attack pattern detection (brute force, web attacks, DDoS, malware)
    - Policy violation detection
    - Anomaly detection (temporal, volume)
    - Reconnaissance detection
    - Data exfiltration patterns
    - MITRE ATT&CK mapping
    - Cluster correlations (attack chains, shared sources/targets)
    - Executive summary with priorities
    """
    if job_id not in trained_models:
        if job_id in training_jobs:
            status = training_jobs[job_id]["status"]
            if status != "completed":
                raise HTTPException(
                    status_code=400,
                    detail=f"Training not completed. Status: {status}"
                )
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[job_id]
    events = model_data["events"]
    labels = model_data["labels"]
    latent = model_data["latent"]
    
    # Group events by cluster
    events_by_cluster = defaultdict(list)
    for event, label in zip(events, labels):
        events_by_cluster[int(label)].append(event)
    
    # Extract insights for each cluster
    all_insights = []
    for cluster_id, cluster_events in events_by_cluster.items():
        cluster_latent = latent[labels == cluster_id] if latent is not None else None
        insights = insights_engine.analyze_cluster_insights(
            cluster_id, 
            cluster_events,
            cluster_latent
        )
        all_insights.extend(insights)
    
    # Find cluster correlations
    correlations = insights_engine.find_cluster_correlations(
        model_data.get("profiles", []),
        events_by_cluster
    )
    
    # Generate executive summary
    executive_summary = insights_engine.generate_executive_summary(
        all_insights,
        len(events_by_cluster),
        len(events)
    )
    
    # Generate threat landscape
    threat_landscape = _generate_threat_landscape(all_insights, events_by_cluster)
    
    # Convert to response format
    insights_response = [
        InsightResponse(
            insight_id=i.insight_id,
            category=i.category,
            title=i.title,
            description=i.description,
            severity=i.severity,
            confidence=i.confidence,
            event_count=i.event_count,
            sample_events=i.sample_events,
            affected_subsystems=i.affected_subsystems,
            source_ips=i.source_ips,
            target_assets=i.target_assets,
            mitre_tactics=i.mitre_tactics,
            mitre_techniques=i.mitre_techniques,
            immediate_actions=i.immediate_actions,
            long_term_actions=i.long_term_actions,
            ioc_indicators=i.ioc_indicators
        )
        for i in all_insights
    ]
    
    correlations_response = [
        CorrelationResponse(
            cluster_a=c.cluster_a,
            cluster_b=c.cluster_b,
            correlation_type=c.correlation_type,
            correlation_strength=c.correlation_strength,
            shared_indicators=c.shared_indicators,
            description=c.description
        )
        for c in correlations
    ]
    
    return FullInsightsResponse(
        job_id=job_id,
        total_events=len(events),
        total_clusters=len(events_by_cluster),
        insights=insights_response,
        correlations=correlations_response,
        executive_summary=executive_summary,
        threat_landscape=threat_landscape
    )


def _generate_threat_landscape(
    insights: list[SecurityInsight],
    events_by_cluster: dict
) -> dict:
    """Generate threat landscape overview"""
    # Attack types detected
    attack_types = defaultdict(int)
    for i in insights:
        if i.category == "attack":
            attack_types[i.title.split(":")[0].strip()] += i.event_count
    
    # Severity timeline (if we had timestamps, we'd use them)
    severity_distribution = defaultdict(int)
    for i in insights:
        severity_distribution[i.severity] += 1
    
    # Top affected subsystems
    subsystem_impact = defaultdict(lambda: {"event_count": 0, "insight_count": 0})
    for i in insights:
        for subsys in i.affected_subsystems:
            subsystem_impact[subsys]["insight_count"] += 1
            subsystem_impact[subsys]["event_count"] += i.event_count
    
    # Top threat sources
    source_threats = defaultdict(lambda: {"insights": [], "total_events": 0})
    for i in insights:
        for ip in i.source_ips:
            source_threats[ip]["insights"].append(i.title)
            source_threats[ip]["total_events"] += i.event_count
    
    top_sources = sorted(
        source_threats.items(),
        key=lambda x: x[1]["total_events"],
        reverse=True
    )[:10]
    
    # Most targeted assets
    target_impact = defaultdict(lambda: {"insights": [], "total_events": 0})
    for i in insights:
        for ip in i.target_assets:
            target_impact[ip]["insights"].append(i.title)
            target_impact[ip]["total_events"] += i.event_count
    
    top_targets = sorted(
        target_impact.items(),
        key=lambda x: x[1]["total_events"],
        reverse=True
    )[:10]
    
    return {
        "attack_types_detected": dict(attack_types),
        "severity_distribution": dict(severity_distribution),
        "subsystem_impact": dict(subsystem_impact),
        "top_threat_sources": [
            {"ip": ip, "insights": data["insights"][:3], "total_events": data["total_events"]}
            for ip, data in top_sources
        ],
        "most_targeted_assets": [
            {"ip": ip, "insights": data["insights"][:3], "total_events": data["total_events"]}
            for ip, data in top_targets
        ],
        "cluster_risk_scores": {
            cluster_id: _calculate_cluster_risk(events)
            for cluster_id, events in events_by_cluster.items()
        }
    }


def _calculate_cluster_risk(events: list[SecurityEvent]) -> dict:
    """Calculate risk score for a cluster"""
    risk_score = 0
    factors = []
    
    blocked_count = sum(1 for e in events if e.action and e.action.lower() in ["blocked", "denied", "drop"])
    total = len(events)
    
    if blocked_count / total > 0.8:
        risk_score += 20
        factors.append("High block rate")
    
    # Check for high severity
    critical_count = sum(1 for e in events if e.severity and e.severity.lower() == "critical")
    high_count = sum(1 for e in events if e.severity and e.severity.lower() == "high")
    
    if critical_count > 0:
        risk_score += 40
        factors.append(f"{critical_count} critical events")
    if high_count > 0:
        risk_score += 20
        factors.append(f"{high_count} high severity events")
    
    # Check for suspicious subsystems
    subsystems = set(e.subsystem.lower() for e in events if e.subsystem)
    if "ips" in subsystems or "ids" in subsystems:
        risk_score += 15
        factors.append("IPS/IDS alerts")
    if "ddos" in subsystems:
        risk_score += 25
        factors.append("DDoS events")
    
    # Check content for threats
    threat_content = sum(1 for e in events if e.content and any(
        kw in e.content.lower() 
        for kw in ["attack", "exploit", "malware", "intrusion", "breach"]
    ))
    if threat_content > total * 0.1:
        risk_score += 20
        factors.append("Threat keywords in content")
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 75:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "score": risk_score,
        "level": risk_level,
        "factors": factors,
        "event_count": total
    }


@app.get("/insights/{job_id}/cluster/{cluster_id}")
async def get_cluster_insights(job_id: str, cluster_id: int):
    """Get detailed security insights for a specific cluster"""
    if job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[job_id]
    events = model_data["events"]
    labels = model_data["labels"]
    latent = model_data["latent"]
    
    # Get cluster events
    cluster_events = [e for e, l in zip(events, labels) if int(l) == cluster_id]
    
    if not cluster_events:
        raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found")
    
    # Get cluster latent features
    cluster_latent = latent[labels == cluster_id] if latent is not None else None
    
    # Extract insights
    insights = insights_engine.analyze_cluster_insights(
        cluster_id,
        cluster_events,
        cluster_latent
    )
    
    # Get cluster profile
    profile = next(
        (p for p in model_data.get("profiles", []) if p.cluster_id == cluster_id),
        None
    )
    
    return {
        "cluster_id": cluster_id,
        "event_count": len(cluster_events),
        "profile": {
            "primary_subsystems": profile.primary_subsystems if profile else [],
            "primary_actions": profile.primary_actions if profile else [],
            "severity_distribution": profile.severity_distribution if profile else {},
            "top_source_ips": profile.top_source_ips if profile else [],
            "top_dest_ports": profile.top_dest_ports if profile else [],
            "threat_level": profile.threat_level if profile else "unknown",
        } if profile else None,
        "insights": [
            {
                "insight_id": i.insight_id,
                "category": i.category,
                "title": i.title,
                "description": i.description,
                "severity": i.severity,
                "confidence": i.confidence,
                "mitre_tactics": i.mitre_tactics,
                "mitre_techniques": i.mitre_techniques,
                "immediate_actions": i.immediate_actions,
                "long_term_actions": i.long_term_actions,
                "ioc_indicators": i.ioc_indicators,
            }
            for i in insights
        ],
        "risk_assessment": _calculate_cluster_risk(cluster_events),
        "sample_events": [
            {
                "timestamp": e.timestamp,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "dest_port": e.dest_port,
                "subsystem": e.subsystem,
                "action": e.action,
                "severity": e.severity,
                "content": e.content[:200] if e.content else ""
            }
            for e in cluster_events[:10]
        ]
    }


@app.get("/insights/{job_id}/iocs")
async def get_indicators_of_compromise(job_id: str):
    """
    Extract all Indicators of Compromise (IOCs) from the analysis.
    Returns IP addresses, patterns, and other indicators that can be
    used for threat intelligence and blocking.
    """
    if job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[job_id]
    events = model_data["events"]
    labels = model_data["labels"]
    
    # Group events by cluster
    events_by_cluster = defaultdict(list)
    for event, label in zip(events, labels):
        events_by_cluster[int(label)].append(event)
    
    # Collect all IOCs
    all_iocs = {
        "malicious_ips": defaultdict(lambda: {"contexts": [], "event_count": 0, "severity": "low"}),
        "targeted_ports": defaultdict(lambda: {"attack_types": [], "event_count": 0}),
        "attack_patterns": [],
        "suspicious_users": defaultdict(lambda: {"reasons": [], "event_count": 0}),
    }
    
    for cluster_id, cluster_events in events_by_cluster.items():
        insights = insights_engine.analyze_cluster_insights(cluster_id, cluster_events)
        
        for insight in insights:
            # Collect malicious IPs
            for ioc in insight.ioc_indicators:
                if ioc.get("type") == "ip":
                    ip = ioc.get("value")
                    all_iocs["malicious_ips"][ip]["contexts"].append(ioc.get("context", "unknown"))
                    all_iocs["malicious_ips"][ip]["event_count"] += insight.event_count
                    if insight.severity in ["critical", "high"]:
                        all_iocs["malicious_ips"][ip]["severity"] = insight.severity
            
            # Collect attack patterns
            if insight.category == "attack":
                all_iocs["attack_patterns"].append({
                    "pattern": insight.title,
                    "description": insight.description[:200],
                    "mitre_techniques": insight.mitre_techniques,
                    "source_ips": insight.source_ips[:5],
                    "severity": insight.severity
                })
    
    # Analyze for suspicious users
    user_events = defaultdict(list)
    for event in events:
        if event.user:
            user_events[event.user].append(event)
    
    for user, user_evts in user_events.items():
        blocked = sum(1 for e in user_evts if e.action and e.action.lower() in ["blocked", "denied"])
        if blocked / len(user_evts) > 0.5:
            all_iocs["suspicious_users"][user]["reasons"].append("High block rate")
            all_iocs["suspicious_users"][user]["event_count"] = len(user_evts)
    
    # Format response
    return {
        "job_id": job_id,
        "generated_at": datetime.now().isoformat(),
        "malicious_ips": [
            {
                "ip": ip,
                "contexts": list(set(data["contexts"]))[:5],
                "event_count": data["event_count"],
                "severity": data["severity"],
                "recommendation": "Block at firewall"
            }
            for ip, data in sorted(
                all_iocs["malicious_ips"].items(),
                key=lambda x: x[1]["event_count"],
                reverse=True
            )[:50]
        ],
        "attack_patterns": all_iocs["attack_patterns"][:20],
        "suspicious_users": [
            {
                "user": user,
                "reasons": data["reasons"],
                "event_count": data["event_count"]
            }
            for user, data in all_iocs["suspicious_users"].items()
        ],
        "firewall_rules": _generate_firewall_rules(all_iocs),
        "total_unique_threat_ips": len(all_iocs["malicious_ips"]),
        "total_attack_patterns": len(all_iocs["attack_patterns"])
    }


def _generate_firewall_rules(iocs: dict) -> list[dict]:
    """Generate suggested firewall rules based on IOCs"""
    rules = []
    
    # Block malicious IPs
    critical_ips = [
        ip for ip, data in iocs["malicious_ips"].items()
        if data["severity"] in ["critical", "high"]
    ]
    
    if critical_ips:
        rules.append({
            "rule_type": "block_ips",
            "priority": 1,
            "description": "Block high-severity threat sources",
            "ips": critical_ips[:20],
            "direction": "inbound"
        })
    
    # Other rules based on attack patterns
    has_brute_force = any("Brute Force" in p.get("pattern", "") for p in iocs.get("attack_patterns", []))
    if has_brute_force:
        rules.append({
            "rule_type": "rate_limit",
            "priority": 2,
            "description": "Rate limit authentication endpoints",
            "ports": [22, 23, 3389, 21],
            "max_connections_per_minute": 10
        })
    
    has_web_attack = any("Web Application" in p.get("pattern", "") for p in iocs.get("attack_patterns", []))
    if has_web_attack:
        rules.append({
            "rule_type": "waf_update",
            "priority": 2,
            "description": "Enable strict WAF rules for SQL injection and XSS",
            "action": "enable_owasp_rules"
        })
    
    return rules


@app.get("/insights/{job_id}/mitre")
async def get_mitre_mapping(job_id: str):
    """
    Get MITRE ATT&CK framework mapping for all detected threats.
    Provides tactical and technique coverage analysis.
    """
    if job_id not in trained_models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model_data = trained_models[job_id]
    events = model_data["events"]
    labels = model_data["labels"]
    
    # Group events by cluster
    events_by_cluster = defaultdict(list)
    for event, label in zip(events, labels):
        events_by_cluster[int(label)].append(event)
    
    # Collect MITRE mappings
    tactics_coverage = defaultdict(lambda: {"techniques": [], "insights": [], "event_count": 0})
    techniques_detail = defaultdict(lambda: {"insights": [], "clusters": [], "event_count": 0})
    
    for cluster_id, cluster_events in events_by_cluster.items():
        insights = insights_engine.analyze_cluster_insights(cluster_id, cluster_events)
        
        for insight in insights:
            for tactic in insight.mitre_tactics:
                tactics_coverage[tactic]["techniques"].extend(insight.mitre_techniques)
                tactics_coverage[tactic]["insights"].append(insight.title)
                tactics_coverage[tactic]["event_count"] += insight.event_count
            
            for technique in insight.mitre_techniques:
                techniques_detail[technique]["insights"].append(insight.title)
                techniques_detail[technique]["clusters"].append(cluster_id)
                techniques_detail[technique]["event_count"] += insight.event_count
    
    # Format tactics
    tactics_formatted = {}
    for tactic, data in tactics_coverage.items():
        tactics_formatted[tactic] = {
            "techniques": list(set(data["techniques"])),
            "insights": list(set(data["insights"]))[:5],
            "event_count": data["event_count"]
        }
    
    # Format techniques
    techniques_formatted = {}
    for technique, data in techniques_detail.items():
        techniques_formatted[technique] = {
            "insights": list(set(data["insights"]))[:5],
            "clusters": list(set(data["clusters"])),
            "event_count": data["event_count"]
        }
    
    # Kill chain analysis
    kill_chain = _analyze_kill_chain(list(tactics_coverage.keys()))
    
    return {
        "job_id": job_id,
        "tactics_coverage": tactics_formatted,
        "techniques_detected": techniques_formatted,
        "total_tactics": len(tactics_coverage),
        "total_techniques": len(techniques_detail),
        "kill_chain_analysis": kill_chain,
        "coverage_assessment": _assess_mitre_coverage(tactics_formatted),
        "mitigation_priorities": _generate_mitre_mitigations(techniques_formatted)
    }


def _analyze_kill_chain(tactics: list[str]) -> dict:
    """Analyze attack progression through kill chain"""
    kill_chain_stages = {
        "reconnaissance": ["Reconnaissance", "Discovery"],
        "weaponization": [],
        "delivery": ["Initial Access"],
        "exploitation": ["Execution", "Privilege Escalation"],
        "installation": ["Persistence", "Defense Evasion"],
        "command_control": ["Command and Control"],
        "actions_on_objectives": ["Collection", "Exfiltration", "Impact"]
    }
    
    detected_stages = []
    for stage, stage_tactics in kill_chain_stages.items():
        if any(t in tactics for t in stage_tactics):
            detected_stages.append(stage)
    
    return {
        "stages_detected": detected_stages,
        "attack_progression": len(detected_stages) / len(kill_chain_stages) * 100,
        "assessment": (
            "Active multi-stage attack detected" if len(detected_stages) >= 4
            else "Partial attack activity" if len(detected_stages) >= 2
            else "Limited threat activity"
        )
    }


def _assess_mitre_coverage(tactics: dict) -> dict:
    """Assess overall MITRE coverage"""
    high_impact_tactics = ["Initial Access", "Execution", "Persistence", "Exfiltration", "Impact"]
    detected_high_impact = [t for t in high_impact_tactics if t in tactics]
    
    return {
        "high_impact_tactics_detected": detected_high_impact,
        "high_impact_coverage": len(detected_high_impact) / len(high_impact_tactics) * 100,
        "overall_risk": (
            "Critical" if len(detected_high_impact) >= 3
            else "High" if len(detected_high_impact) >= 2
            else "Medium" if len(detected_high_impact) >= 1
            else "Low"
        )
    }


def _generate_mitre_mitigations(techniques: dict) -> list[dict]:
    """Generate prioritized mitigations based on detected techniques"""
    mitigations = []
    
    technique_mitigations = {
        "T1110 - Brute Force": [
            "Implement account lockout policies",
            "Enable multi-factor authentication",
            "Monitor for multiple failed authentication attempts"
        ],
        "T1190 - Exploit Public-Facing Application": [
            "Keep applications patched and updated",
            "Use Web Application Firewall (WAF)",
            "Conduct regular vulnerability assessments"
        ],
        "T1498 - Network Denial of Service": [
            "Implement rate limiting",
            "Use DDoS protection services",
            "Configure network traffic filtering"
        ],
        "T1071 - Application Layer Protocol": [
            "Monitor network traffic for anomalies",
            "Implement network segmentation",
            "Use endpoint detection and response (EDR)"
        ],
    }
    
    for technique, data in sorted(techniques.items(), key=lambda x: -x[1]["event_count"]):
        if technique in technique_mitigations:
            mitigations.append({
                "technique": technique,
                "event_count": data["event_count"],
                "recommended_mitigations": technique_mitigations[technique]
            })
    
    return mitigations[:10]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(root_app, host="0.0.0.0", port=8000)
