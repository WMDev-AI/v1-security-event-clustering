"""
Training Pipeline for Deep Clustering Models
Handles pretraining, fine-tuning, and evaluation
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import (
    normalized_mutual_info_score,
    adjusted_rand_score,
    silhouette_score,
    davies_bouldin_score,
    calinski_harabasz_score,
)
from sklearn.cluster import KMeans
from sklearn.mixture import GaussianMixture
from sklearn.cluster import AgglomerativeClustering
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum
import asyncio
import inspect
import time

from deep_clustering import (
    DeepEmbeddedClustering,
    ImprovedDEC,
    VaDE,
    ContrastiveDeepClustering,
    DeepUFCM,
    DeepMultiViewClustering,
    SecurityEventAutoEncoder,
    BarlowTwinsGuidedFilterClustering,
    reconstruction_loss,
    kl_divergence_loss,
    vae_loss,
    cluster_assignment_entropy
)
from sequence_clustering import ImprovedDECSequence, DeepUFCMSequence
from gnn_clustering import ImprovedDECGNN


class ModelType(str, Enum):
    DEC = "dec"
    IDEC = "idec"
    VADE = "vade"
    CONTRASTIVE = "contrastive"
    UFCM = "ufcm"
    UFCM_LSTM = "ufcm_lstm"
    DMVC = "dmvc"
    IDEC_LSTM = "idec_lstm"
    IDEC_TRANSFORMER = "idec_transformer"
    IDEC_GNN = "idec_gnn"
    BTGF = "btgf"


@dataclass
class TrainingConfig:
    """Configuration for training deep clustering models"""
    # Model architecture
    hidden_dims: list[int] = None
    latent_dim: int = 32
    n_clusters: int = 10
    dropout: float = 0.2
    
    # Pretraining
    pretrain_epochs: int = 50
    pretrain_lr: float = 1e-3
    pretrain_batch_size: int = 256
    
    # Fine-tuning
    finetune_epochs: int = 100
    finetune_lr: float = 1e-4
    finetune_batch_size: int = 256
    
    # DEC/IDEC / DMVC specific
    alpha: float = 1.0
    gamma: float = 0.1  # Weight for reconstruction loss in IDEC / DMVC
    mvc_weight: float = 0.1  # Multi-view latent alignment (DMVC)
    update_interval: int = 5  # Update target distribution every N epochs
    tol: float = 0.001  # Stopping tolerance
    
    # VaDE specific
    beta: float = 1.0  # KL weight in VAE
    
    # Contrastive specific
    temperature: float = 0.5

    # UFCM (Unconstrained Fuzzy C-Means on latent space)
    fuzziness_m: float = 2.0  # FCM fuzzifier, must be > 1
    ufcm_recon_weight: float = 0.1  # Reconstruction regularizer (like IDEC)

    # Sequence IDEC (LSTM / Transformer over temporal windows [T, D])
    seq_len: int = 16
    seq_hidden: int = 128
    lstm_layers: int = 2
    transformer_heads: int = 4
    transformer_layers: int = 2

    # GNN-IDEC (within-batch k-NN graph + GCN encoder)
    gnn_k_neighbors: int = 10
    gnn_hidden_dim: int = 128
    gnn_num_layers: int = 2
    
    # BTGF specific
    btgf_k: int = 2  # Filter iterations
    btgf_a: float = 100.0  # Regularization
    btgf_f: int = 1  # Filter order
    btgf_lambda_rec: float = 1.0
    btgf_lambda_bt: float = 1.0
    btgf_lambda_kl: float = 1.0
    btgf_num_relations: int = 2  # Number of relations/views
    
    # General
    weight_decay: float = 1e-5
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    
    def __post_init__(self):
        if self.hidden_dims is None:
            self.hidden_dims = [256, 128, 64]


class ClusteringMetrics:
    """Compute clustering evaluation metrics"""
    
    @staticmethod
    def compute_all(
        labels_pred: np.ndarray,
        labels_true: Optional[np.ndarray] = None,
        features: Optional[np.ndarray] = None
    ) -> dict:
        """Compute all available metrics"""
        metrics = {}
        
        # External metrics (require ground truth)
        if labels_true is not None:
            metrics['nmi'] = float(normalized_mutual_info_score(labels_true, labels_pred))
            metrics['ari'] = float(adjusted_rand_score(labels_true, labels_pred))
        
        # Internal metrics
        if features is not None and len(np.unique(labels_pred)) > 1:
            try:
                metrics['silhouette'] = float(silhouette_score(features, labels_pred))
            except Exception:
                metrics['silhouette'] = -1.0
            try:
                metrics['davies_bouldin'] = float(davies_bouldin_score(features, labels_pred))
            except Exception:
                metrics['davies_bouldin'] = -1.0
            try:
                metrics['calinski_harabasz'] = float(calinski_harabasz_score(features, labels_pred))
            except Exception:
                metrics['calinski_harabasz'] = -1.0
        
        # Cluster distribution
        unique, counts = np.unique(labels_pred, return_counts=True)
        metrics['n_clusters_found'] = len(unique)
        metrics['cluster_sizes'] = dict(zip(unique.tolist(), counts.tolist()))
        metrics['size_std'] = float(np.std(counts))
        metrics['size_min'] = int(np.min(counts))
        metrics['size_max'] = int(np.max(counts))
        
        return metrics


class DeepClusteringTrainer:
    """
    Trainer for deep clustering models
    Supports DEC, IDEC, VaDE, and Contrastive approaches
    """
    
    def __init__(
        self,
        input_dim: int,
        model_type: ModelType,
        config: TrainingConfig = None
    ):
        self.input_dim = input_dim
        self.model_type = model_type
        self.config = config or TrainingConfig()
        self.device = torch.device(self.config.device)
        
        # Initialize model based on type
        self.model = self._create_model()
        self.model.to(self.device)
        
        # Training state
        self.history = {
            'pretrain_loss': [],
            'clustering_loss': [],
            'reconstruction_loss': [],
            'total_loss': [],
            'metrics': []
        }
        
        self.is_pretrained = False
        self.is_clusters_initialized = False

    def _uses_sequence_encoder(self) -> bool:
        return self.model_type in (
            ModelType.IDEC_LSTM,
            ModelType.IDEC_TRANSFORMER,
            ModelType.UFCM_LSTM,
        )
    
    def _create_model(self) -> nn.Module:
        """Create model based on type"""
        if self.model_type == ModelType.DEC:
            return DeepEmbeddedClustering(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                alpha=self.config.alpha,
                dropout=self.config.dropout
            )
        elif self.model_type == ModelType.IDEC:
            return ImprovedDEC(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                alpha=self.config.alpha,
                gamma=self.config.gamma,
                dropout=self.config.dropout
            )
        elif self.model_type == ModelType.VADE:
            return VaDE(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                dropout=self.config.dropout
            )
        elif self.model_type == ModelType.CONTRASTIVE:
            return ContrastiveDeepClustering(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                temperature=self.config.temperature,
                dropout=self.config.dropout
            )
        elif self.model_type == ModelType.UFCM:
            return DeepUFCM(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                dropout=self.config.dropout,
                fuzziness_m=self.config.fuzziness_m,
            )
        elif self.model_type == ModelType.UFCM_LSTM:
            return DeepUFCMSequence(
                input_dim=self.input_dim,
                seq_len=self.config.seq_len,
                n_clusters=self.config.n_clusters,
                seq_hidden=self.config.seq_hidden,
                latent_dim=self.config.latent_dim,
                dropout=self.config.dropout,
                fuzziness_m=self.config.fuzziness_m,
                lstm_layers=self.config.lstm_layers,
                transformer_heads=self.config.transformer_heads,
                transformer_layers=self.config.transformer_layers,
            )
        elif self.model_type == ModelType.DMVC:
            return DeepMultiViewClustering(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                alpha=self.config.alpha,
                dropout=self.config.dropout,
            )
        elif self.model_type == ModelType.IDEC_LSTM:
            return ImprovedDECSequence(
                input_dim=self.input_dim,
                seq_len=self.config.seq_len,
                n_clusters=self.config.n_clusters,
                seq_hidden=self.config.seq_hidden,
                latent_dim=self.config.latent_dim,
                alpha=self.config.alpha,
                gamma=self.config.gamma,
                dropout=self.config.dropout,
                encoder_type="lstm",
                lstm_layers=self.config.lstm_layers,
                transformer_heads=self.config.transformer_heads,
                transformer_layers=self.config.transformer_layers,
            )
        elif self.model_type == ModelType.IDEC_TRANSFORMER:
            return ImprovedDECSequence(
                input_dim=self.input_dim,
                seq_len=self.config.seq_len,
                n_clusters=self.config.n_clusters,
                seq_hidden=self.config.seq_hidden,
                latent_dim=self.config.latent_dim,
                alpha=self.config.alpha,
                gamma=self.config.gamma,
                dropout=self.config.dropout,
                encoder_type="transformer",
                lstm_layers=self.config.lstm_layers,
                transformer_heads=self.config.transformer_heads,
                transformer_layers=self.config.transformer_layers,
            )
        elif self.model_type == ModelType.IDEC_GNN:
            return ImprovedDECGNN(
                input_dim=self.input_dim,
                n_clusters=self.config.n_clusters,
                hidden_dims=self.config.hidden_dims,
                latent_dim=self.config.latent_dim,
                gnn_hidden_dim=self.config.gnn_hidden_dim,
                n_gnn_layers=self.config.gnn_num_layers,
                k_neighbors=self.config.gnn_k_neighbors,
                alpha=self.config.alpha,
                gamma=self.config.gamma,
                dropout=self.config.dropout,
            )
        elif self.model_type == ModelType.BTGF:
            input_dims = [self.input_dim] * self.config.btgf_num_relations
            return BarlowTwinsGuidedFilterClustering(
                input_dims=input_dims,
                latent_dim=self.config.latent_dim,
                num_clusters=self.config.n_clusters,
                dropout=self.config.dropout,
                lambda_rec=self.config.btgf_lambda_rec,
                lambda_bt=self.config.btgf_lambda_bt,
                lambda_kl=self.config.btgf_lambda_kl
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    async def pretrain(
        self,
        data: np.ndarray,
        progress_callback: Optional[Callable[[int, float], Awaitable[None]]] = None
    ):
        """
        Pretrain the autoencoder for reconstruction
        
        Args:
            data: Training data [n_samples, n_features]
            progress_callback: Optional async callback(epoch, loss) for progress reporting
        """
        print(f"Pretraining autoencoder for {self.config.pretrain_epochs} epochs...")
        
        # Prepare data
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(
            dataset, 
            batch_size=self.config.pretrain_batch_size, 
            shuffle=True,
            drop_last=True
        )
        
        # Get autoencoder
        if self.model_type == ModelType.VADE:
            autoencoder = self.model.vae
        elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
            autoencoder = self.model.autoencoder
        elif self.model_type == ModelType.CONTRASTIVE:
            # For contrastive, we pretrain the encoder differently
            await self._pretrain_contrastive(loader, progress_callback)
            self.is_pretrained = True
            return
        elif self.model_type == ModelType.DMVC:
            await self._pretrain_dmvc(loader, progress_callback)
            self.is_pretrained = True
            print("Pretraining complete!")
            return
        elif self.model_type == ModelType.BTGF:
            # Pretrain each MLP with reconstruction
            optimizer = optim.Adam(
                self.model.parameters(),
                lr=self.config.pretrain_lr,
                weight_decay=self.config.weight_decay
            )
            scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)
            
            self.model.train()
            for epoch in range(self.config.pretrain_epochs):
                epoch_loss = 0.0
                n_batches = 0
                
                for batch in loader:
                    x = batch[0].to(self.device)
                    # Use same x for all relations during pretrain
                    X_list = [x] * self.config.btgf_num_relations
                    
                    optimizer.zero_grad()
                    z_list, x_bar_list, _ = self.model(X_list)
                    loss = self.model.reconstruction_loss(X_list, x_bar_list)
                    loss.backward()
                    optimizer.step()
                    
                    epoch_loss += loss.item()
                    n_batches += 1
                
                scheduler.step()
                avg_loss = epoch_loss / n_batches
                self.history['pretrain_loss'].append(avg_loss)
                
                if progress_callback:
                    if inspect.iscoroutinefunction(progress_callback):
                        await progress_callback(epoch, avg_loss)
                    else:
                        progress_callback(epoch, avg_loss)
                
                if (epoch + 1) % 10 == 0:
                    print(f"BTGF Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}")
            
            self.is_pretrained = True
            print("BTGF pretraining complete!")
            return
        else:
            autoencoder = self.model.autoencoder if hasattr(self.model, 'autoencoder') else self.model.dec.autoencoder
        
        optimizer = optim.Adam(
            autoencoder.parameters(),
            lr=self.config.pretrain_lr,
            weight_decay=self.config.weight_decay
        )
        scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)
        
        autoencoder.train()
        for epoch in range(self.config.pretrain_epochs):
            epoch_loss = 0.0
            n_batches = 0
            
            for batch in loader:
                x = batch[0].to(self.device)
                
                optimizer.zero_grad()
                
                if self.model_type == ModelType.VADE:
                    z, x_recon, mu, logvar = autoencoder(x)
                    loss = vae_loss(x, x_recon, mu, logvar, self.config.beta)
                else:
                    z, x_recon = autoencoder(x)
                    target = x[:, -1, :] if self._uses_sequence_encoder() else x
                    loss = reconstruction_loss(target, x_recon)
                
                loss.backward()
                optimizer.step()
                
                epoch_loss += loss.item()
                n_batches += 1
            
            avg_loss = epoch_loss / n_batches
            self.history['pretrain_loss'].append(avg_loss)
            scheduler.step()
            
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(epoch, avg_loss)
                else:
                    progress_callback(epoch, avg_loss)
            
            if (epoch + 1) % 10 == 0:
                print(f"Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}")
        
        self.is_pretrained = True
        print("Pretraining complete!")
    
    async def _pretrain_contrastive(
        self,
        loader: DataLoader,
        progress_callback: Optional[Callable[[int, float], Awaitable[None]]] = None
    ):
        """Pretrain contrastive model with augmentation"""
        optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.config.pretrain_lr,
            weight_decay=self.config.weight_decay
        )
        
        self.model.train()
        for epoch in range(self.config.pretrain_epochs):
            epoch_loss = 0.0
            n_batches = 0
            
            for batch in loader:
                x = batch[0].to(self.device)
                
                # Create augmented views (simple dropout-based augmentation)
                x1 = F.dropout(x, p=0.1, training=True)
                x2 = F.dropout(x, p=0.1, training=True)
                
                optimizer.zero_grad()
                
                _, proj1, _ = self.model(x1)
                _, proj2, _ = self.model(x2)
                
                loss = self.model.contrastive_loss(proj1, proj2)
                
                loss.backward()
                optimizer.step()
                
                epoch_loss += loss.item()
                n_batches += 1
            
            avg_loss = epoch_loss / n_batches
            self.history['pretrain_loss'].append(avg_loss)
            
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(epoch, avg_loss)
                else:
                    progress_callback(epoch, avg_loss)
            
            if (epoch + 1) % 10 == 0:
                print(f"Contrastive Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}")

    async def _pretrain_dmvc(
        self,
        loader: DataLoader,
        progress_callback: Optional[Callable[[int, float], Awaitable[None]]] = None,
    ):
        """Pretrain both view autoencoders with reconstruction only."""
        params = list(self.model.ae1.parameters()) + list(self.model.ae2.parameters())
        optimizer = optim.Adam(
            params,
            lr=self.config.pretrain_lr,
            weight_decay=self.config.weight_decay,
        )
        scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)
        dim_v1 = self.model.dim_v1
        self.model.ae1.train()
        self.model.ae2.train()
        for epoch in range(self.config.pretrain_epochs):
            epoch_loss = 0.0
            n_batches = 0
            for batch in loader:
                x = batch[0].to(self.device)
                x1 = x[:, :dim_v1]
                x2 = x[:, dim_v1:]
                optimizer.zero_grad()
                _, r1 = self.model.ae1(x1)
                _, r2 = self.model.ae2(x2)
                loss = reconstruction_loss(x1, r1) + reconstruction_loss(x2, r2)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1
            avg_loss = epoch_loss / max(n_batches, 1)
            self.history["pretrain_loss"].append(avg_loss)
            scheduler.step()
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(epoch, avg_loss)
                else:
                    progress_callback(epoch, avg_loss)
            if (epoch + 1) % 10 == 0:
                print(
                    f"DMVC Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}"
                )
    
    async def initialize_clusters(self, data: np.ndarray, progress_callback: Optional[Callable[[float], Awaitable[None]]] = None) -> np.ndarray:
        """Initialize cluster centers using K-Means on latent space
        
        Args:
            data: Training data
            progress_callback: Optional async callback(progress_pct) for progress updates (0-100)
        """
        print("Initializing cluster centers...")
        
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        if self.model_type == ModelType.VADE:
            initial_labels = self.model.initialize_gmm(loader, self.device)
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(100)
                else:
                    progress_callback(100)
        elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
            initial_labels = self.model.initialize_clusters(loader, self.device)
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(100)
                else:
                    progress_callback(100)
        elif self.model_type == ModelType.CONTRASTIVE:
            # K-Means on latent space
            self.model.eval()
            latent_vectors = []
            total_batches = len(loader)
            
            with torch.no_grad():
                for i, batch in enumerate(loader):
                    x = batch[0].to(self.device)
                    z = self.model.encode(x)
                    latent_vectors.append(z.cpu().numpy())
                    
                    # Report progress during encoding
                    if progress_callback:
                        encode_progress = ((i + 1) / total_batches) * 30  # First 30%
                        if inspect.iscoroutinefunction(progress_callback):
                            await progress_callback(encode_progress)
                        else:
                            progress_callback(encode_progress)
            
            latent_vectors = np.concatenate(latent_vectors, axis=0)
            
            from sklearn.cluster import KMeans
            
            # Custom K-Means with progress callback
            best_inertia = float('inf')
            best_labels = None
            n_init = min(20, max(3, len(latent_vectors) // 1000))  # Adaptive n_init based on data size
            
            for init_idx in range(n_init):
                kmeans = KMeans(n_clusters=self.config.n_clusters, n_init=1, random_state=42 + init_idx, max_iter=300)
                labels = kmeans.fit_predict(latent_vectors)
                
                if kmeans.inertia_ < best_inertia:
                    best_inertia = kmeans.inertia_
                    best_labels = labels
                
                # Report progress during K-Means iterations
                if progress_callback:
                    kmeans_progress = 30 + ((init_idx + 1) / n_init) * 70  # 30-100%
                    if inspect.iscoroutinefunction(progress_callback):
                        await progress_callback(min(100, kmeans_progress))
                    else:
                        progress_callback(min(100, kmeans_progress))
            
            initial_labels = best_labels
        else:
            initial_labels = self.model.initialize_clusters(loader, self.device)
            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(100)
                else:
                    progress_callback(100)
        
        self.is_clusters_initialized = True
        print(f"Clusters initialized. Distribution: {np.bincount(initial_labels)}")
        return initial_labels
    
    async def finetune(
        self,
        data: np.ndarray,
        labels_true: Optional[np.ndarray] = None,
        progress_callback: Optional[Callable[[int, dict], Awaitable[None]]] = None
    ):
        """
        Fine-tune with clustering objective
        
        Args:
            data: Training data
            labels_true: Optional ground truth labels for evaluation
            progress_callback: Optional async callback(epoch, metrics) for progress
        """
        if not self.is_pretrained:
            print("Warning: Model not pretrained. Running pretraining first...")
            await self.pretrain(data)
        
        if not self.is_clusters_initialized:
            await self.initialize_clusters(data)
        
        print(f"Fine-tuning for {self.config.finetune_epochs} epochs...")
        
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(
            dataset,
            batch_size=self.config.finetune_batch_size,
            shuffle=True,
            drop_last=True
        )
        
        optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.config.finetune_lr,
            weight_decay=self.config.weight_decay
        )
        
        # For checking convergence
        prev_labels = None
        
        self.model.train()
        for epoch in range(self.config.finetune_epochs):
            # Compute target distribution periodically
            if self.model_type in [
                ModelType.DEC,
                ModelType.IDEC,
                ModelType.DMVC,
                ModelType.IDEC_LSTM,
                ModelType.IDEC_TRANSFORMER,
                ModelType.IDEC_GNN,
            ]:
                if epoch % self.config.update_interval == 0:
                    target_dist = self._compute_target_distribution(data)
            
            epoch_losses = {'total': 0.0, 'clustering': 0.0, 'reconstruction': 0.0}
            n_batches = 0
            batch_idx = 0
            
            for batch in loader:
                x = batch[0].to(self.device)
                
                optimizer.zero_grad()
                
                if self.model_type == ModelType.DEC:
                    q, z, x_recon = self.model(x)
                    p = target_dist[batch_idx * self.config.finetune_batch_size:
                                   (batch_idx + 1) * self.config.finetune_batch_size].to(self.device)
                    loss = kl_divergence_loss(q, p)
                    epoch_losses['clustering'] += loss.item()
                    
                elif self.model_type == ModelType.IDEC:
                    q, z, x_recon = self.model(x)
                    p = target_dist[batch_idx * self.config.finetune_batch_size:
                                   (batch_idx + 1) * self.config.finetune_batch_size].to(self.device)
                    kl_loss = kl_divergence_loss(q, p)
                    recon_loss = reconstruction_loss(x, x_recon)
                    loss = kl_loss + self.config.gamma * recon_loss
                    epoch_losses['clustering'] += kl_loss.item()
                    epoch_losses['reconstruction'] += recon_loss.item()

                elif self.model_type == ModelType.IDEC_GNN:
                    q, z, x_recon = self.model(x)
                    p = target_dist[batch_idx * self.config.finetune_batch_size:
                                   (batch_idx + 1) * self.config.finetune_batch_size].to(self.device)
                    kl_loss = kl_divergence_loss(q, p)
                    recon_loss = reconstruction_loss(x, x_recon)
                    loss = kl_loss + self.config.gamma * recon_loss
                    epoch_losses['clustering'] += kl_loss.item()
                    epoch_losses['reconstruction'] += recon_loss.item()

                elif self.model_type in (ModelType.IDEC_LSTM, ModelType.IDEC_TRANSFORMER):
                    q, z, x_recon = self.model(x)
                    p = target_dist[batch_idx * self.config.finetune_batch_size:
                                   (batch_idx + 1) * self.config.finetune_batch_size].to(self.device)
                    x_target = x[:, -1, :]
                    kl_loss = kl_divergence_loss(q, p)
                    recon_loss = reconstruction_loss(x_target, x_recon)
                    loss = kl_loss + self.config.gamma * recon_loss
                    epoch_losses['clustering'] += kl_loss.item()
                    epoch_losses['reconstruction'] += recon_loss.item()

                elif self.model_type == ModelType.DMVC:
                    q, z, x_recon, z1, z2 = self.model(x)
                    p = target_dist[batch_idx * self.config.finetune_batch_size:
                                   (batch_idx + 1) * self.config.finetune_batch_size].to(self.device)
                    kl_loss = kl_divergence_loss(q, p)
                    recon_loss = reconstruction_loss(x, x_recon)
                    mvc_loss = F.mse_loss(z1, z2)
                    loss = (
                        kl_loss
                        + self.config.gamma * recon_loss
                        + self.config.mvc_weight * mvc_loss
                    )
                    epoch_losses['clustering'] += (
                        kl_loss.item() + self.config.mvc_weight * mvc_loss.item()
                    )
                    epoch_losses['reconstruction'] += recon_loss.item()
                    
                elif self.model_type == ModelType.VADE:
                    z, x_recon, mu, logvar, gamma = self.model(x)
                    loss = self._vade_loss(x, x_recon, mu, logvar, gamma)
                    epoch_losses['clustering'] += loss.item()
                    
                elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
                    u, z, x_recon = self.model(x)
                    sq = self.model.squared_distances(z)
                    m = self.model.fuzziness_m
                    ufcm_loss = (u.pow(m) * sq).sum(dim=1).mean()
                    x_target = x[:, -1, :] if self.model_type == ModelType.UFCM_LSTM else x
                    recon_loss = reconstruction_loss(x_target, x_recon)
                    loss = (
                        ufcm_loss
                        + self.config.ufcm_recon_weight * recon_loss
                    )
                    epoch_losses["clustering"] += ufcm_loss.item()
                    epoch_losses["reconstruction"] += recon_loss.item()

                elif self.model_type == ModelType.CONTRASTIVE:
                    # Augmentation
                    x1 = F.dropout(x, p=0.1, training=True)
                    x2 = F.dropout(x, p=0.1, training=True)
                    
                    z1, proj1, c1 = self.model(x1)
                    z2, proj2, c2 = self.model(x2)
                    
                    contrastive_loss = self.model.contrastive_loss(proj1, proj2)
                    # Consistency loss for cluster assignments
                    consistency_loss = F.mse_loss(c1, c2)
                    # Entropy regularization to avoid degenerate solutions
                    entropy_loss = -cluster_assignment_entropy((c1 + c2) / 2)
                    
                    loss = contrastive_loss + 0.5 * consistency_loss + 0.1 * entropy_loss
                    epoch_losses['clustering'] += loss.item()
                
                elif self.model_type == ModelType.BTGF:
                    # Create multiple views with augmentation
                    X_list = []
                    for _ in range(self.config.btgf_num_relations):
                        x_aug = x + torch.randn_like(x) * 0.1  # Add noise for augmentation
                        X_list.append(x_aug)
                    
                    z_list, x_bar_list, h = self.model(X_list)
                    loss, q = self.model.total_loss(X_list, z_list, x_bar_list, h, x.size(0))
                    epoch_losses['total'] += loss.item()
                    epoch_losses['clustering'] += loss.item()  # Approximate
                    
                loss.backward()
                optimizer.step()
                
                epoch_losses['total'] += loss.item()
                n_batches += 1
                batch_idx += 1
            
            # Average losses
            for key in epoch_losses:
                epoch_losses[key] /= n_batches
            
            self.history['total_loss'].append(epoch_losses['total'])
            self.history['clustering_loss'].append(epoch_losses['clustering'])
            self.history['reconstruction_loss'].append(epoch_losses['reconstruction'])

            # Progress payload every epoch (loss always; intrinsic metrics on eval cadence)
            report = {
                "total_loss": float(epoch_losses['total']),
                "clustering_loss": float(epoch_losses['clustering']),
                "reconstruction_loss": float(epoch_losses['reconstruction']),
            }
            if (epoch + 1) % 5 == 0:
                metrics = self._evaluate(data, labels_true)
                self.history['metrics'].append(metrics)
                report.update(metrics)

                silhouette_val = metrics.get('silhouette')
                if isinstance(silhouette_val, (int, float)):
                    silhouette_display = f"{silhouette_val:.4f}"
                else:
                    silhouette_display = "N/A"

                print(
                    f"Epoch {epoch + 1}/{self.config.finetune_epochs}, "
                    f"Loss: {epoch_losses['total']:.6f}, "
                    f"Silhouette: {silhouette_display}"
                )

                current_labels = self.predict(data)
                if prev_labels is not None:
                    delta = np.sum(current_labels != prev_labels) / len(current_labels)
                    if delta < self.config.tol:
                        print(f"Converged at epoch {epoch + 1} (delta={delta:.6f})")
                        break
                prev_labels = current_labels
            elif self.history.get("metrics"):
                # Keep last intrinsic metrics in UI between eval epochs
                report.update(self.history["metrics"][-1])

            if progress_callback:
                if inspect.iscoroutinefunction(progress_callback):
                    await progress_callback(epoch, report)
                else:
                    progress_callback(epoch, report)

        print("Fine-tuning complete!")
    
    def _compute_target_distribution(self, data: np.ndarray) -> torch.Tensor:
        """Compute target distribution P from current soft assignments Q"""
        self.model.eval()
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        q_list = []
        with torch.no_grad():
            for batch in loader:
                x = batch[0].to(self.device)
                if self.model_type in [ModelType.DEC, ModelType.IDEC]:
                    q, _, _ = self.model(x)
                    q_list.append(q.cpu())
                elif self.model_type in (ModelType.IDEC_LSTM, ModelType.IDEC_TRANSFORMER):
                    q, _, _ = self.model(x)
                    q_list.append(q.cpu())
                elif self.model_type == ModelType.DMVC:
                    q, _, _, _, _ = self.model(x)
                    q_list.append(q.cpu())
                elif self.model_type == ModelType.IDEC_GNN:
                    q, _, _ = self.model(x)
                    q_list.append(q.cpu())
        
        q_all = torch.cat(q_list, dim=0)
        p = self.model.clustering_layer.get_target_distribution(q_all)
        
        self.model.train()
        return p
    
    def _vade_loss(
        self,
        x: torch.Tensor,
        x_recon: torch.Tensor,
        mu: torch.Tensor,
        logvar: torch.Tensor,
        gamma: torch.Tensor
    ) -> torch.Tensor:
        """ELBO loss for VaDE"""
        # Reconstruction loss
        recon = reconstruction_loss(x, x_recon)
        
        # KL divergence for encoder
        kl_encoder = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
        
        # Expected log-likelihood of GMM
        # This is simplified; full VaDE loss is more complex
        log_gamma = torch.log(gamma + 1e-10)
        cluster_loss = -torch.mean(torch.sum(gamma * log_gamma, dim=1))
        
        return recon + self.config.beta * kl_encoder + 0.1 * cluster_loss
    
    def _evaluate(
        self,
        data: np.ndarray,
        labels_true: Optional[np.ndarray] = None
    ) -> dict:
        """Evaluate current clustering performance"""
        labels_pred = self.predict(data)
        latent = self.get_latent_representations(data)
        
        return ClusteringMetrics.compute_all(labels_pred, labels_true, latent)

    async def refine_cluster_assignments(
        self,
        latent: np.ndarray,
        initial_labels: np.ndarray,
        n_trials: int = 8,
        min_gain: float = 0.01,
        max_search_seconds: float = 8.0,
        silhouette_sample_size: int = 1500,
        progress_callback: Optional[Callable[[float], Awaitable[None]]] = None,
    ) -> tuple[np.ndarray, dict]:
        """
        Refine cluster assignments in latent space using multiple K-Means restarts.
        Uses the assignment with the best silhouette score when it improves enough.
        """
        result = {
            "applied": False,
            "method": "model_predict",
            "silhouette_before": -1.0,
            "silhouette_after": -1.0,
            "silhouette_gain": 0.0,
            "elapsed_seconds": 0.0,
            "time_budget_hit": False,
        }

        if latent is None or len(latent) < 3:
            return initial_labels, result

        unique_labels = np.unique(initial_labels)
        if len(unique_labels) < 2:
            return initial_labels, result

        start_time = time.perf_counter()

        def is_timeout() -> bool:
            return (time.perf_counter() - start_time) >= max_search_seconds

        async def report_progress(pct: float) -> None:
            if progress_callback:
                try:
                    value = float(max(0.0, min(100.0, pct)))
                    maybe_awaitable = progress_callback(value)
                    if inspect.isawaitable(maybe_awaitable):
                        await maybe_awaitable
                except Exception:
                    pass

        def score_partition(features: np.ndarray, labels: np.ndarray) -> float:
            """Fast silhouette scoring with adaptive sampling under time budget."""
            if len(np.unique(labels)) < 2:
                return -1.0
            try:
                n = len(labels)
                if n > silhouette_sample_size:
                    return float(
                        silhouette_score(
                            features,
                            labels,
                            sample_size=silhouette_sample_size,
                            random_state=42,
                        )
                    )
                return float(silhouette_score(features, labels))
            except Exception:
                return -1.0

        # Normalize latent space for metric stability and K-Means distance quality.
        latent_scaled = latent.astype(np.float32, copy=False)
        latent_scaled = (latent_scaled - latent_scaled.mean(axis=0)) / (latent_scaled.std(axis=0) + 1e-8)

        base_score = score_partition(latent_scaled, initial_labels)

        best_labels = initial_labels
        best_score = base_score
        n_clusters = len(unique_labels)

        # Tighten search to stay within 5-10s budget.
        kmeans_trials = max(1, min(4, n_trials))
        gmm_trials = max(1, min(2, n_trials // 2))
        total_steps = kmeans_trials + gmm_trials + (1 if len(latent_scaled) <= 3500 else 0)
        completed_steps = 0
        await report_progress(5.0)

        for trial in range(kmeans_trials):
            if is_timeout():
                result["time_budget_hit"] = True
                break
            try:
                kmeans = KMeans(
                    n_clusters=n_clusters,
                    n_init=1,
                    random_state=42 + trial,
                    max_iter=150
                )
                candidate_labels = kmeans.fit_predict(latent_scaled)

                if len(np.unique(candidate_labels)) < 2:
                    continue

                candidate_score = score_partition(latent_scaled, candidate_labels)
                if candidate_score > best_score:
                    best_score = candidate_score
                    best_labels = candidate_labels
            except Exception:
                continue
            finally:
                completed_steps += 1
                await report_progress(5.0 + 90.0 * (completed_steps / max(1, total_steps)))

        # Gaussian Mixture candidates in latent space.
        for trial in range(gmm_trials):
            if is_timeout():
                result["time_budget_hit"] = True
                break
            try:
                gmm = GaussianMixture(
                    n_components=n_clusters,
                    covariance_type="full",
                    reg_covar=1e-5,
                    max_iter=120,
                    random_state=101 + trial,
                )
                candidate_labels = gmm.fit_predict(latent_scaled)
                if len(np.unique(candidate_labels)) < 2:
                    continue
                candidate_score = score_partition(latent_scaled, candidate_labels)
                if candidate_score > best_score:
                    best_score = candidate_score
                    best_labels = candidate_labels
            except Exception:
                continue
            finally:
                completed_steps += 1
                await report_progress(5.0 + 90.0 * (completed_steps / max(1, total_steps)))

        # Agglomerative can be expensive; only run on moderate N and if budget allows.
        if not is_timeout() and len(latent_scaled) <= 3500:
            try:
                agg = AgglomerativeClustering(n_clusters=n_clusters, linkage="ward")
                candidate_labels = agg.fit_predict(latent_scaled)
                if len(np.unique(candidate_labels)) > 1:
                    candidate_score = score_partition(latent_scaled, candidate_labels)
                    if candidate_score > best_score:
                        best_score = candidate_score
                        best_labels = candidate_labels
            except Exception:
                pass
            finally:
                completed_steps += 1
                await report_progress(5.0 + 90.0 * (completed_steps / max(1, total_steps)))

        result["silhouette_before"] = base_score
        result["silhouette_after"] = best_score
        result["silhouette_gain"] = float(best_score - base_score)
        result["elapsed_seconds"] = float(time.perf_counter() - start_time)
        await report_progress(100.0)

        if result["silhouette_gain"] >= min_gain:
            result["applied"] = True
            result["method"] = "latent_ensemble_refinement"
            return best_labels.astype(np.int64, copy=False), result

        return initial_labels, result
    
    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict cluster assignments for data"""
        self.model.eval()
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        predictions = []
        with torch.no_grad():
            for batch in loader:
                x = batch[0].to(self.device)
                
                if self.model_type in [ModelType.DEC, ModelType.IDEC]:
                    q, _, _ = self.model(x)
                    pred = q.argmax(dim=1)
                elif self.model_type == ModelType.IDEC_GNN:
                    q, _, _ = self.model(x)
                    pred = q.argmax(dim=1)
                elif self.model_type in (ModelType.IDEC_LSTM, ModelType.IDEC_TRANSFORMER):
                    q, _, _ = self.model(x)
                    pred = q.argmax(dim=1)
                elif self.model_type == ModelType.DMVC:
                    q, _, _, _, _ = self.model(x)
                    pred = q.argmax(dim=1)
                elif self.model_type == ModelType.VADE:
                    _, _, _, _, gamma = self.model(x)
                    pred = gamma.argmax(dim=1)
                elif self.model_type == ModelType.CONTRASTIVE:
                    _, _, cluster_prob = self.model(x)
                    pred = cluster_prob.argmax(dim=1)
                elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
                    u, _, _ = self.model(x)
                    pred = u.argmax(dim=1)

                elif self.model_type == ModelType.BTGF:
                    # Create multiple views
                    X_list = []
                    for _ in range(self.config.btgf_num_relations):
                        x_aug = x + torch.randn_like(x) * 0.1
                        X_list.append(x_aug)
                    _, _, h = self.model(X_list)
                    q = self.model.get_cluster_prob(h)
                    pred = q.argmax(dim=1)

                predictions.append(pred.cpu().numpy())
        
        return np.concatenate(predictions, axis=0)
    
    def get_cluster_probabilities(self, data: np.ndarray) -> np.ndarray:
        """Get soft cluster assignment probabilities"""
        self.model.eval()
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        probs = []
        with torch.no_grad():
            for batch in loader:
                x = batch[0].to(self.device)
                
                if self.model_type in [ModelType.DEC, ModelType.IDEC]:
                    q, _, _ = self.model(x)
                    probs.append(q.cpu().numpy())
                elif self.model_type == ModelType.IDEC_GNN:
                    q, _, _ = self.model(x)
                    probs.append(q.cpu().numpy())
                elif self.model_type in (ModelType.IDEC_LSTM, ModelType.IDEC_TRANSFORMER):
                    q, _, _ = self.model(x)
                    probs.append(q.cpu().numpy())
                elif self.model_type == ModelType.DMVC:
                    q, _, _, _, _ = self.model(x)
                    probs.append(q.cpu().numpy())
                elif self.model_type == ModelType.VADE:
                    _, _, _, _, gamma = self.model(x)
                    probs.append(gamma.cpu().numpy())
                elif self.model_type == ModelType.CONTRASTIVE:
                    _, _, cluster_prob = self.model(x)
                    probs.append(cluster_prob.cpu().numpy())
                elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
                    u, _, _ = self.model(x)
                    probs.append(u.cpu().numpy())

                elif self.model_type == ModelType.BTGF:
                    # Create multiple views
                    X_list = []
                    for _ in range(self.config.btgf_num_relations):
                        x_aug = x + torch.randn_like(x) * 0.1
                        X_list.append(x_aug)
                    _, _, h = self.model(X_list)
                    q = self.model.get_cluster_prob(h)
                    probs.append(q.cpu().numpy())

        return np.concatenate(probs, axis=0)
    
    def get_latent_representations(self, data: np.ndarray) -> np.ndarray:
        """Get latent representations for data"""
        self.model.eval()
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        latent = []
        with torch.no_grad():
            for batch in loader:
                x = batch[0].to(self.device)
                
                if self.model_type == ModelType.BTGF:
                    # Create multiple views
                    X_list = []
                    for _ in range(self.config.btgf_num_relations):
                        x_aug = x + torch.randn_like(x) * 0.1
                        X_list.append(x_aug)
                    _, _, h = self.model(X_list)
                    latent.append(h.cpu().numpy())
                else:
                    z = self.model.encode(x)
                    latent.append(z.cpu().numpy())
        
        return np.concatenate(latent, axis=0)
    
    def get_cluster_centers(self) -> Optional[np.ndarray]:
        """Get cluster centers if available"""
        if self.model_type in [
            ModelType.DEC,
            ModelType.IDEC,
            ModelType.DMVC,
            ModelType.IDEC_LSTM,
            ModelType.IDEC_TRANSFORMER,
            ModelType.IDEC_GNN,
            ModelType.BTGF,
        ]:
            return self.model.clustering_layer.cluster_centers.detach().cpu().numpy()
        elif self.model_type == ModelType.VADE:
            return self.model.mu_c.detach().cpu().numpy()
        elif self.model_type in (ModelType.UFCM, ModelType.UFCM_LSTM):
            return self.model.cluster_centers.detach().cpu().numpy()
        return None
    
    def save_model(self, path: str):
        """Save model state"""
        torch.save({
            'model_state': self.model.state_dict(),
            'model_type': self.model_type.value,
            'config': self.config,
            'history': self.history,
            'is_pretrained': self.is_pretrained,
            'is_clusters_initialized': self.is_clusters_initialized
        }, path)
    
    def load_model(self, path: str):
        """Load model state"""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state'])
        self.history = checkpoint['history']
        self.is_pretrained = checkpoint['is_pretrained']
        self.is_clusters_initialized = checkpoint['is_clusters_initialized']


# Import F for dropout
import torch.nn.functional as F
