"""
Deep Clustering Models for Security Event Analysis
Implements multiple deep clustering approaches using PyTorch
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.cluster import KMeans
from typing import Optional, Tuple
from abc import ABC, abstractmethod


class BaseAutoEncoder(nn.Module, ABC):
    """Base autoencoder class for deep clustering"""
    
    @abstractmethod
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input to latent representation"""
        pass
    
    @abstractmethod
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """Decode latent representation to reconstruction"""
        pass
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Forward pass returning both latent and reconstruction"""
        z = self.encode(x)
        x_recon = self.decode(z)
        return z, x_recon


class SecurityEventAutoEncoder(BaseAutoEncoder):
    """
    Deep Autoencoder specifically designed for security event data
    Uses layer-wise pretraining capability
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        dropout: float = 0.2,
        activation: str = 'relu'
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims
        self.latent_dim = latent_dim
        
        # Select activation function
        if activation == 'relu':
            self.activation = nn.ReLU()
        elif activation == 'leaky_relu':
            self.activation = nn.LeakyReLU(0.1)
        elif activation == 'elu':
            self.activation = nn.ELU()
        else:
            self.activation = nn.ReLU()
        
        # Build encoder
        encoder_layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                self.activation,
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        encoder_layers.append(nn.Linear(prev_dim, latent_dim))
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Build decoder (mirror of encoder)
        decoder_layers = []
        prev_dim = latent_dim
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                self.activation,
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)
    
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)


class VariationalAutoEncoder(BaseAutoEncoder):
    """
    Variational Autoencoder for probabilistic latent representations
    Better for capturing uncertainty in security events
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        dropout: float = 0.2
    ):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        
        # Build encoder
        encoder_layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        self.encoder_base = nn.Sequential(*encoder_layers)
        
        # Latent distribution parameters
        self.fc_mu = nn.Linear(prev_dim, latent_dim)
        self.fc_logvar = nn.Linear(prev_dim, latent_dim)
        
        # Build decoder
        decoder_layers = []
        prev_dim = latent_dim
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
        
        self.training_mode = True
    
    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """Reparameterization trick for VAE"""
        if self.training_mode:
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std
        return mu
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        h = self.encoder_base(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        z = self.reparameterize(mu, logvar)
        return z
    
    def encode_with_params(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Encode and return latent along with distribution parameters"""
        h = self.encoder_base(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        z = self.reparameterize(mu, logvar)
        return z, mu, logvar
    
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        z, mu, logvar = self.encode_with_params(x)
        x_recon = self.decode(z)
        return z, x_recon, mu, logvar


class ClusteringLayer(nn.Module):
    """
    Clustering layer for Deep Embedded Clustering (DEC)
    Computes soft cluster assignments using Student's t-distribution
    """
    
    def __init__(self, n_clusters: int, latent_dim: int, alpha: float = 1.0):
        super().__init__()
        self.n_clusters = n_clusters
        self.alpha = alpha
        
        # Cluster centers (learnable)
        self.cluster_centers = nn.Parameter(
            torch.zeros(n_clusters, latent_dim)
        )
    
    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Compute soft cluster assignments using Student's t-distribution
        
        Args:
            z: Latent representations [batch_size, latent_dim]
            
        Returns:
            q: Soft cluster assignments [batch_size, n_clusters]
        """
        # Compute distances to cluster centers
        # z: [batch_size, latent_dim]
        # cluster_centers: [n_clusters, latent_dim]
        
        # Expand for broadcasting
        z_expanded = z.unsqueeze(1)  # [batch_size, 1, latent_dim]
        centers_expanded = self.cluster_centers.unsqueeze(0)  # [1, n_clusters, latent_dim]
        
        # Squared Euclidean distance
        dist_sq = torch.sum((z_expanded - centers_expanded) ** 2, dim=2)  # [batch_size, n_clusters]
        
        # Student's t-distribution kernel (df=alpha)
        q = 1.0 / (1.0 + dist_sq / self.alpha)
        q = q ** ((self.alpha + 1.0) / 2.0)
        
        # Normalize to get soft assignments
        q = q / q.sum(dim=1, keepdim=True)
        
        return q
    
    def get_target_distribution(self, q: torch.Tensor) -> torch.Tensor:
        """
        Compute target distribution P from soft assignments Q
        This sharpens the cluster assignments
        """
        weight = q ** 2 / q.sum(dim=0, keepdim=True)
        p = weight / weight.sum(dim=1, keepdim=True)
        return p


class DeepEmbeddedClustering(nn.Module):
    """
    Deep Embedded Clustering (DEC) Model
    
    Two-phase training:
    1. Pretrain autoencoder for reconstruction
    2. Fine-tune with clustering loss (KL divergence)
    """
    
    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        alpha: float = 1.0,
        dropout: float = 0.2
    ):
        super().__init__()
        
        self.autoencoder = SecurityEventAutoEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout
        )
        
        self.clustering_layer = ClusteringLayer(
            n_clusters=n_clusters,
            latent_dim=latent_dim,
            alpha=alpha
        )
        
        self.n_clusters = n_clusters
        self.latent_dim = latent_dim
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Get latent representation"""
        return self.autoencoder.encode(x)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass
        
        Returns:
            q: Soft cluster assignments
            z: Latent representations
            x_recon: Reconstruction
        """
        z, x_recon = self.autoencoder(x)
        q = self.clustering_layer(z)
        return q, z, x_recon
    
    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
        """Initialize cluster centers using K-Means on latent representations"""
        self.eval()
        latent_vectors = []
        
        with torch.no_grad():
            for batch in data_loader:
                if isinstance(batch, (list, tuple)):
                    x = batch[0].to(device)
                else:
                    x = batch.to(device)
                z = self.encode(x)
                latent_vectors.append(z.cpu().numpy())
        
        latent_vectors = np.concatenate(latent_vectors, axis=0)
        
        # K-Means initialization
        kmeans = KMeans(n_clusters=self.n_clusters, n_init=20, random_state=42)
        kmeans.fit(latent_vectors)
        
        # Set cluster centers
        self.clustering_layer.cluster_centers.data = torch.tensor(
            kmeans.cluster_centers_, dtype=torch.float32
        ).to(device)
        
        return kmeans.labels_


class ImprovedDEC(nn.Module):
    """
    Improved Deep Embedded Clustering (IDEC)
    Combines reconstruction loss with clustering loss for better performance
    """
    
    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        alpha: float = 1.0,
        gamma: float = 0.1,  # Weight for clustering loss
        dropout: float = 0.2
    ):
        super().__init__()
        
        self.dec = DeepEmbeddedClustering(
            input_dim=input_dim,
            n_clusters=n_clusters,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            alpha=alpha,
            dropout=dropout
        )
        
        self.gamma = gamma
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        return self.dec(x)
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.dec.encode(x)
    
    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
        return self.dec.initialize_clusters(data_loader, device)
    
    @property
    def clustering_layer(self):
        return self.dec.clustering_layer
    
    @property
    def autoencoder(self):
        return self.dec.autoencoder


class VaDE(nn.Module):
    """
    Variational Deep Embedding (VaDE)
    Combines VAE with Gaussian Mixture Model for probabilistic clustering
    """
    
    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        dropout: float = 0.2
    ):
        super().__init__()
        
        self.n_clusters = n_clusters
        self.latent_dim = latent_dim
        
        # VAE backbone
        self.vae = VariationalAutoEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout
        )
        
        # GMM parameters
        self.pi = nn.Parameter(torch.ones(n_clusters) / n_clusters)  # Mixture weights
        self.mu_c = nn.Parameter(torch.zeros(n_clusters, latent_dim))  # Cluster means
        self.logvar_c = nn.Parameter(torch.zeros(n_clusters, latent_dim))  # Cluster log-variances
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass
        
        Returns:
            z: Latent representation
            x_recon: Reconstruction
            mu: Encoder mean
            logvar: Encoder log-variance
            gamma: Cluster responsibilities
        """
        z, x_recon, mu, logvar = self.vae(x)
        gamma = self.get_gamma(z)
        return z, x_recon, mu, logvar, gamma
    
    def get_gamma(self, z: torch.Tensor) -> torch.Tensor:
        """Compute cluster responsibilities (posterior q(c|z))"""
        # z: [batch_size, latent_dim]
        batch_size = z.shape[0]
        
        # Log prior
        log_pi = F.log_softmax(self.pi, dim=0)  # [n_clusters]
        
        # Log likelihood p(z|c)
        z_expanded = z.unsqueeze(1)  # [batch_size, 1, latent_dim]
        mu_c_expanded = self.mu_c.unsqueeze(0)  # [1, n_clusters, latent_dim]
        logvar_c_expanded = self.logvar_c.unsqueeze(0)  # [1, n_clusters, latent_dim]
        
        # Log Gaussian likelihood
        log_p_z_c = -0.5 * (
            logvar_c_expanded + 
            np.log(2 * np.pi) + 
            torch.exp(-logvar_c_expanded) * (z_expanded - mu_c_expanded) ** 2
        )
        log_p_z_c = log_p_z_c.sum(dim=2)  # [batch_size, n_clusters]
        
        # Posterior q(c|z) ∝ p(c) * p(z|c)
        log_gamma = log_pi.unsqueeze(0) + log_p_z_c
        gamma = F.softmax(log_gamma, dim=1)
        
        return gamma
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.vae.encode(x)
    
    def initialize_gmm(self, data_loader: DataLoader, device: torch.device):
        """Initialize GMM parameters using K-Means"""
        self.eval()
        latent_vectors = []
        
        with torch.no_grad():
            for batch in data_loader:
                if isinstance(batch, (list, tuple)):
                    x = batch[0].to(device)
                else:
                    x = batch.to(device)
                z = self.encode(x)
                latent_vectors.append(z.cpu().numpy())
        
        latent_vectors = np.concatenate(latent_vectors, axis=0)
        
        # K-Means initialization
        kmeans = KMeans(n_clusters=self.n_clusters, n_init=20, random_state=42)
        labels = kmeans.fit_predict(latent_vectors)
        
        # Initialize cluster means
        self.mu_c.data = torch.tensor(
            kmeans.cluster_centers_, dtype=torch.float32
        ).to(device)
        
        # Initialize cluster variances (using within-cluster variance)
        for k in range(self.n_clusters):
            cluster_points = latent_vectors[labels == k]
            if len(cluster_points) > 1:
                var = np.var(cluster_points, axis=0) + 1e-6
                self.logvar_c.data[k] = torch.tensor(np.log(var), dtype=torch.float32).to(device)
        
        # Initialize mixture weights
        counts = np.bincount(labels, minlength=self.n_clusters)
        self.pi.data = torch.tensor(counts / counts.sum(), dtype=torch.float32).to(device)
        
        return labels


class ContrastiveDeepClustering(nn.Module):
    """
    Contrastive Deep Clustering
    Uses contrastive learning to learn better representations for clustering
    """
    
    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = [256, 128, 64],
        latent_dim: int = 32,
        projection_dim: int = 64,
        temperature: float = 0.5,
        dropout: float = 0.2
    ):
        super().__init__()
        
        self.n_clusters = n_clusters
        self.temperature = temperature
        
        # Encoder backbone
        self.encoder = SecurityEventAutoEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout
        ).encoder
        
        # Projection head for contrastive learning
        self.projection_head = nn.Sequential(
            nn.Linear(latent_dim, latent_dim),
            nn.ReLU(),
            nn.Linear(latent_dim, projection_dim)
        )
        
        # Cluster head
        self.cluster_head = nn.Sequential(
            nn.Linear(latent_dim, latent_dim),
            nn.ReLU(),
            nn.Linear(latent_dim, n_clusters),
            nn.Softmax(dim=1)
        )
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass
        
        Returns:
            z: Latent representation
            proj: Projected representation for contrastive loss
            cluster_prob: Cluster assignment probabilities
        """
        z = self.encode(x)
        proj = F.normalize(self.projection_head(z), dim=1)
        cluster_prob = self.cluster_head(z)
        return z, proj, cluster_prob
    
    def contrastive_loss(self, proj1: torch.Tensor, proj2: torch.Tensor) -> torch.Tensor:
        """NT-Xent (Normalized Temperature-scaled Cross Entropy) loss"""
        batch_size = proj1.shape[0]
        
        # Concatenate projections
        proj = torch.cat([proj1, proj2], dim=0)  # [2*batch_size, proj_dim]
        
        # Compute similarity matrix
        sim = torch.mm(proj, proj.t()) / self.temperature  # [2*batch_size, 2*batch_size]
        
        # Mask out self-similarity
        mask = torch.eye(2 * batch_size, dtype=torch.bool, device=proj.device)
        sim = sim.masked_fill(mask, float('-inf'))
        
        # Positive pairs: (i, i+batch_size) and (i+batch_size, i)
        labels = torch.cat([
            torch.arange(batch_size, 2 * batch_size),
            torch.arange(batch_size)
        ]).to(proj.device)
        
        loss = F.cross_entropy(sim, labels)
        return loss


# Loss functions for deep clustering

def reconstruction_loss(x: torch.Tensor, x_recon: torch.Tensor) -> torch.Tensor:
    """MSE reconstruction loss"""
    return F.mse_loss(x_recon, x)


def kl_divergence_loss(q: torch.Tensor, p: torch.Tensor) -> torch.Tensor:
    """KL divergence between soft assignments Q and target distribution P"""
    return torch.mean(torch.sum(p * torch.log(p / (q + 1e-10) + 1e-10), dim=1))


def vae_loss(x: torch.Tensor, x_recon: torch.Tensor, 
             mu: torch.Tensor, logvar: torch.Tensor, beta: float = 1.0) -> torch.Tensor:
    """VAE ELBO loss"""
    recon = reconstruction_loss(x, x_recon)
    kl = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
    return recon + beta * kl


def cluster_assignment_entropy(q: torch.Tensor) -> torch.Tensor:
    """Entropy of cluster assignments (for regularization)"""
    avg_probs = q.mean(dim=0)
    return -torch.sum(avg_probs * torch.log(avg_probs + 1e-10))
