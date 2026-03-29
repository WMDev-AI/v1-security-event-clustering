"""
Training Pipeline for Deep Clustering Models
Handles pretraining, fine-tuning, and evaluation
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import normalized_mutual_info_score, adjusted_rand_score, silhouette_score
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum

from deep_clustering import (
    DeepEmbeddedClustering,
    ImprovedDEC,
    VaDE,
    ContrastiveDeepClustering,
    SecurityEventAutoEncoder,
    reconstruction_loss,
    kl_divergence_loss,
    vae_loss,
    cluster_assignment_entropy
)


class ModelType(str, Enum):
    DEC = "dec"
    IDEC = "idec"
    VADE = "vade"
    CONTRASTIVE = "contrastive"


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
    
    # DEC/IDEC specific
    alpha: float = 1.0
    gamma: float = 0.1  # Weight for reconstruction loss in IDEC
    update_interval: int = 5  # Update target distribution every N epochs
    tol: float = 0.001  # Stopping tolerance
    
    # VaDE specific
    beta: float = 1.0  # KL weight in VAE
    
    # Contrastive specific
    temperature: float = 0.5
    
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
            metrics['nmi'] = normalized_mutual_info_score(labels_true, labels_pred)
            metrics['ari'] = adjusted_rand_score(labels_true, labels_pred)
        
        # Internal metrics
        if features is not None and len(np.unique(labels_pred)) > 1:
            try:
                metrics['silhouette'] = silhouette_score(features, labels_pred)
            except Exception:
                metrics['silhouette'] = -1.0
        
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
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def pretrain(
        self,
        data: np.ndarray,
        progress_callback: Optional[Callable[[int, float], None]] = None
    ):
        """
        Pretrain the autoencoder for reconstruction
        
        Args:
            data: Training data [n_samples, n_features]
            progress_callback: Optional callback(epoch, loss) for progress reporting
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
        elif self.model_type == ModelType.CONTRASTIVE:
            # For contrastive, we pretrain the encoder differently
            self._pretrain_contrastive(loader, progress_callback)
            self.is_pretrained = True
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
                    loss = reconstruction_loss(x, x_recon)
                
                loss.backward()
                optimizer.step()
                
                epoch_loss += loss.item()
                n_batches += 1
            
            avg_loss = epoch_loss / n_batches
            self.history['pretrain_loss'].append(avg_loss)
            scheduler.step()
            
            if progress_callback:
                progress_callback(epoch, avg_loss)
            
            if (epoch + 1) % 10 == 0:
                print(f"Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}")
        
        self.is_pretrained = True
        print("Pretraining complete!")
    
    def _pretrain_contrastive(
        self,
        loader: DataLoader,
        progress_callback: Optional[Callable[[int, float], None]] = None
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
                progress_callback(epoch, avg_loss)
            
            if (epoch + 1) % 10 == 0:
                print(f"Contrastive Pretrain Epoch {epoch + 1}/{self.config.pretrain_epochs}, Loss: {avg_loss:.6f}")
    
    def initialize_clusters(self, data: np.ndarray) -> np.ndarray:
        """Initialize cluster centers using K-Means on latent space"""
        print("Initializing cluster centers...")
        
        dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.config.finetune_batch_size, shuffle=False)
        
        if self.model_type == ModelType.VADE:
            initial_labels = self.model.initialize_gmm(loader, self.device)
        elif self.model_type == ModelType.CONTRASTIVE:
            # K-Means on latent space
            self.model.eval()
            latent_vectors = []
            with torch.no_grad():
                for batch in loader:
                    x = batch[0].to(self.device)
                    z = self.model.encode(x)
                    latent_vectors.append(z.cpu().numpy())
            latent_vectors = np.concatenate(latent_vectors, axis=0)
            
            from sklearn.cluster import KMeans
            kmeans = KMeans(n_clusters=self.config.n_clusters, n_init=20, random_state=42)
            initial_labels = kmeans.fit_predict(latent_vectors)
        else:
            initial_labels = self.model.initialize_clusters(loader, self.device)
        
        self.is_clusters_initialized = True
        print(f"Clusters initialized. Distribution: {np.bincount(initial_labels)}")
        return initial_labels
    
    def finetune(
        self,
        data: np.ndarray,
        labels_true: Optional[np.ndarray] = None,
        progress_callback: Optional[Callable[[int, dict], None]] = None
    ):
        """
        Fine-tune with clustering objective
        
        Args:
            data: Training data
            labels_true: Optional ground truth labels for evaluation
            progress_callback: Optional callback(epoch, metrics) for progress
        """
        if not self.is_pretrained:
            print("Warning: Model not pretrained. Running pretraining first...")
            self.pretrain(data)
        
        if not self.is_clusters_initialized:
            self.initialize_clusters(data)
        
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
            if self.model_type in [ModelType.DEC, ModelType.IDEC]:
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
                    
                elif self.model_type == ModelType.VADE:
                    z, x_recon, mu, logvar, gamma = self.model(x)
                    loss = self._vade_loss(x, x_recon, mu, logvar, gamma)
                    epoch_losses['clustering'] += loss.item()
                    
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
            
            # Compute metrics periodically
            if (epoch + 1) % 5 == 0:
                metrics = self._evaluate(data, labels_true)
                self.history['metrics'].append(metrics)
                
                if progress_callback:
                    progress_callback(epoch, metrics)
                
                print(f"Epoch {epoch + 1}/{self.config.finetune_epochs}, "
                      f"Loss: {epoch_losses['total']:.6f}, "
                      f"Silhouette: {metrics.get('silhouette', 'N/A'):.4f}")
                
                # Check for convergence
                current_labels = self.predict(data)
                if prev_labels is not None:
                    delta = np.sum(current_labels != prev_labels) / len(current_labels)
                    if delta < self.config.tol:
                        print(f"Converged at epoch {epoch + 1} (delta={delta:.6f})")
                        break
                prev_labels = current_labels
        
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
                elif self.model_type == ModelType.VADE:
                    _, _, _, _, gamma = self.model(x)
                    pred = gamma.argmax(dim=1)
                elif self.model_type == ModelType.CONTRASTIVE:
                    _, _, cluster_prob = self.model(x)
                    pred = cluster_prob.argmax(dim=1)
                
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
                elif self.model_type == ModelType.VADE:
                    _, _, _, _, gamma = self.model(x)
                    probs.append(gamma.cpu().numpy())
                elif self.model_type == ModelType.CONTRASTIVE:
                    _, _, cluster_prob = self.model(x)
                    probs.append(cluster_prob.cpu().numpy())
        
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
                z = self.model.encode(x)
                latent.append(z.cpu().numpy())
        
        return np.concatenate(latent, axis=0)
    
    def get_cluster_centers(self) -> Optional[np.ndarray]:
        """Get cluster centers if available"""
        if self.model_type in [ModelType.DEC, ModelType.IDEC]:
            return self.model.clustering_layer.cluster_centers.detach().cpu().numpy()
        elif self.model_type == ModelType.VADE:
            return self.model.mu_c.detach().cpu().numpy()
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
