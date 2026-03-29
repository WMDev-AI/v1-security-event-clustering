"""
Security Event Deep Clustering API
FastAPI backend for processing and clustering security events
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import numpy as np
import torch
from enum import Enum
import uuid
import asyncio
from datetime import datetime

from event_parser import EventParser, SecurityEvent
from deep_clustering import (
    DeepEmbeddedClustering,
    ImprovedDEC,
    VaDE,
    ContrastiveDeepClustering
)
from trainer import DeepClusteringTrainer, TrainingConfig, ModelType, ClusteringMetrics
from cluster_analyzer import ClusterAnalyzer, analyze_clusters_from_results, ClusterProfile

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

# Global state for training jobs
training_jobs = {}
trained_models = {}
parser = EventParser()
analyzer = ClusterAnalyzer(parser)


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
    progress: float
    current_epoch: int
    total_epochs: int
    current_loss: float
    metrics: Optional[dict] = None
    message: str = ""


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
    events: list[SecurityEvent],
    features: np.ndarray,
    config: TrainingConfig,
    model_type: ModelType
):
    """Background task for training deep clustering model"""
    try:
        training_jobs[job_id]["status"] = "training"
        training_jobs[job_id]["message"] = "Initializing trainer..."
        
        trainer = DeepClusteringTrainer(
            input_dim=features.shape[1],
            model_type=model_type,
            config=config
        )
        
        # Pretraining
        training_jobs[job_id]["message"] = "Pretraining autoencoder..."
        total_pretrain = config.pretrain_epochs
        
        def pretrain_callback(epoch, loss):
            training_jobs[job_id]["current_epoch"] = epoch
            training_jobs[job_id]["current_loss"] = loss
            training_jobs[job_id]["progress"] = (epoch + 1) / (total_pretrain + config.finetune_epochs) * 100
        
        trainer.pretrain(features, pretrain_callback)
        
        # Initialize clusters
        training_jobs[job_id]["message"] = "Initializing cluster centers..."
        trainer.initialize_clusters(features)
        
        # Fine-tuning
        training_jobs[job_id]["message"] = "Fine-tuning with clustering objective..."
        
        def finetune_callback(epoch, metrics):
            training_jobs[job_id]["current_epoch"] = total_pretrain + epoch
            training_jobs[job_id]["metrics"] = metrics
            training_jobs[job_id]["progress"] = (total_pretrain + epoch + 1) / (total_pretrain + config.finetune_epochs) * 100
        
        trainer.finetune(features, progress_callback=finetune_callback)
        
        # Get final results
        labels = trainer.predict(features)
        latent = trainer.get_latent_representations(features)
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
            "profiles": profiles,
            "summary": summary,
            "feature_mean": features.mean(axis=0),
            "feature_std": features.std(axis=0) + 1e-8
        }
        
        training_jobs[job_id]["status"] = "completed"
        training_jobs[job_id]["progress"] = 100
        training_jobs[job_id]["message"] = "Training completed successfully"
        training_jobs[job_id]["metrics"] = ClusteringMetrics.compute_all(labels, features=latent)
        
    except Exception as e:
        training_jobs[job_id]["status"] = "failed"
        training_jobs[job_id]["message"] = str(e)
        raise


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
    
    # Parse events
    try:
        events, features = parse_events_to_features(request.events)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing events: {str(e)}")
    
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
    
    # Create job
    job_id = str(uuid.uuid4())
    model_type = ModelType(request.model_type.value)
    
    training_jobs[job_id] = {
        "job_id": job_id,
        "status": "starting",
        "progress": 0,
        "current_epoch": 0,
        "total_epochs": config.pretrain_epochs + config.finetune_epochs,
        "current_loss": 0.0,
        "metrics": None,
        "message": "Parsing events...",
        "model_type": request.model_type.value,
        "n_events": len(events),
        "n_clusters": request.n_clusters,
        "created_at": datetime.now().isoformat()
    }
    
    # Start training in background
    background_tasks.add_task(
        run_training,
        job_id,
        events,
        features,
        config,
        model_type
    )
    
    return {"job_id": job_id, "message": "Training started"}


@app.get("/train/{job_id}")
async def get_training_status(job_id: str):
    """Get training job status"""
    if job_id not in training_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return training_jobs[job_id]


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
