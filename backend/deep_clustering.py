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
from typing import Optional, Tuple, List
from abc import ABC, abstractmethod
import math
from itertools import combinations


def fgc_filter(A: torch.Tensor, X: torch.Tensor, k: int, a: float, f: int = 1) -> torch.Tensor:
    """
    Barlow Twins Guided Filter for graph signal processing.
    A: adjacency matrix [n, n]
    X: feature matrix [n, d]
    k: number of iterations
    a: regularization parameter
    f: filter order
    Returns filtered X
    """
    n = A.size(0)
    d = X.size(1)
    device = A.device
    
    # Identity matrix
    I_n = torch.eye(n, device=device)
    I_d = torch.eye(d, device=device)
    
    # Normalize adjacency
    A = A + I_n  # Add self-loops
    D = A.sum(dim=1, keepdim=True)
    D_norm = D.pow(-0.5)
    A_norm = D_norm * A * D_norm.t()
    
    # Laplacian
    Ls = I_n - A_norm
    G = I_n - 0.5 * Ls
    
    # Polynomial filter
    A_ = I_n
    for _ in range(f):
        A_ = G @ A_
    
    # Iterative refinement
    G_ = G
    for iteration in range(k):
        X_bar = G_ @ X
        XtX_bar = X_bar.t() @ X_bar
        XXt_bar = X_bar @ X_bar.t()
        
        # Inverse computation
        tmp = torch.linalg.inv(I_d + XXt_bar / a)
        tmp = X_bar @ tmp @ X_bar.t()
        tmp = I_n / a - tmp / (a * a)
        
        # Filtered update
        S = tmp @ (a * A_ + XtX_bar)
        G_ = G_ @ G
    
    X_filtered = S @ X
    return X_filtered


def fgc_multi(A_list: List[torch.Tensor], X_list: List[torch.Tensor], k: int, a: float, f: int = 1) -> List[torch.Tensor]:
    """
    Apply filter to multiple relations.
    """
    X_filtered = []
    for A, X in zip(A_list, X_list):
        X_filtered.append(fgc_filter(A, X, k, a, f))
    return X_filtered


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


class BTGFMLP(nn.Module):
    """
    MLP-based autoencoder for BTGF, adapted for multi-relational inputs.
    """
    
    def __init__(self, input_dim: int, latent_dim: int = 10, dropout: float = 0.0):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, latent_dim),
            nn.Dropout(dropout)
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, input_dim),
            nn.Dropout(dropout)
        )
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encoder(x)
        x_recon = self.decoder(z)
        return z, x_recon


class BarlowTwinsGuidedFilterClustering(nn.Module):
    """
    BTGF clustering model for multi-relational security event data.
    """
    
    def __init__(
        self,
        input_dims: List[int],
        latent_dim: int = 10,
        num_clusters: int = 10,
        dropout: float = 0.0,
        lambda_rec: float = 1.0,
        lambda_bt: float = 1.0,
        lambda_kl: float = 1.0
    ):
        super().__init__()
        self.num_relations = len(input_dims)
        self.latent_dim = latent_dim
        self.num_clusters = num_clusters
        self.lambda_rec = lambda_rec
        self.lambda_bt = lambda_bt
        self.lambda_kl = lambda_kl
        
        # MLPs for each relation
        self.mlps = nn.ModuleList([
            BTGFMLP(dim, latent_dim, dropout) for dim in input_dims
        ])
        
        # Clustering layer
        self.cluster_layer = ClusteringLayer(latent_dim * self.num_relations, num_clusters)
    
    def forward(self, X_list: List[torch.Tensor]) -> Tuple[List[torch.Tensor], List[torch.Tensor], torch.Tensor]:
        """
        Forward pass for multi-relational inputs.
        X_list: list of [batch, dim] tensors
        Returns: z_list, x_bar_list, h_concat
        """
        z_list = []
        x_bar_list = []
        for i, X in enumerate(X_list):
            z, x_bar = self.mlps[i](X)
            z_list.append(z)
            x_bar_list.append(x_bar)
        
        # Concatenate embeddings
        h = torch.cat(z_list, dim=1)
        return z_list, x_bar_list, h
    
    def get_cluster_prob(self, h: torch.Tensor) -> torch.Tensor:
        """Get soft cluster assignments"""
        return self.cluster_layer(h)
    
    def barlow_twins_loss(self, z_list: List[torch.Tensor], batch_size: int) -> torch.Tensor:
        """Barlow Twins loss for multi-relational views"""
        loss = 0.0
        bn = nn.BatchNorm1d(self.latent_dim, affine=False)
        for i, j in combinations(range(len(z_list)), 2):
            z_i = bn(z_list[i])
            z_j = bn(z_list[j])
            c = z_i.t() @ z_j / batch_size
            
            # On-diagonal: (diag - 1)^2
            on_diag = torch.sum((torch.diag(c) - 1) ** 2)
            # Off-diagonal: sum of squares
            off_diag = torch.sum(c ** 2) - torch.sum(torch.diag(c) ** 2)
            
            loss += on_diag + 0.0051 * off_diag
        return loss
    
    def sce_loss(self, x: torch.Tensor, x_bar: torch.Tensor, alpha: float = 2.0) -> torch.Tensor:
        """Symmetric cross-entropy loss"""
        cos_sim = F.cosine_similarity(x, x_bar, dim=1)
        loss = (1 - cos_sim) ** alpha
        return loss.mean()
    
    def reconstruction_loss(self, X_list: List[torch.Tensor], x_bar_list: List[torch.Tensor]) -> torch.Tensor:
        """Multi-relational reconstruction loss"""
        loss = 0.0
        for X, x_bar in zip(X_list, x_bar_list):
            loss += self.sce_loss(X, x_bar)
        return loss
    
    def clustering_loss(self, q: torch.Tensor, p: torch.Tensor) -> torch.Tensor:
        """KL divergence for clustering"""
        return F.kl_div(q.log(), p, reduction='batchmean')
    
    def target_distribution(self, q: torch.Tensor) -> torch.Tensor:
        """Student t-distribution target"""
        weight = q ** 2 / q.sum(dim=0)
        return (weight.t() / weight.sum(dim=1)).t()
    
    def total_loss(self, X_list: List[torch.Tensor], z_list: List[torch.Tensor], x_bar_list: List[torch.Tensor], h: torch.Tensor, batch_size: int) -> Tuple[torch.Tensor, torch.Tensor]:
        """Compute total BTGF loss"""
        rec_loss = self.reconstruction_loss(X_list, x_bar_list)
        bt_loss = self.barlow_twins_loss(z_list, batch_size)
        
        q = self.get_cluster_prob(h)
        p = self.target_distribution(q)
        kl_loss = self.clustering_loss(q, p)
        
        total = self.lambda_rec * rec_loss + self.lambda_bt * bt_loss + self.lambda_kl * kl_loss
        return total, q


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


class DeepUFCM(nn.Module):
    """
    Deep Unconstrained Fuzzy C-Means (UC-FCM / UFCM).

    Uses the equivalent unconstrained formulation of Fuzzy C-Means where, for fixed
    cluster centers, the optimal fuzzy membership matrix is substituted into the
    objective. The resulting loss is minimized by gradient descent over centers (and
    optionally the encoder), as in UC-FCM (IEEE TPAMI, 2025).

    FCM uses fuzziness parameter m > 1. Memberships satisfy the usual probabilistic
    constraint sum_k u_ik = 1 per sample, computed from Euclidean distances in latent space.
    """

    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = None,
        latent_dim: int = 32,
        dropout: float = 0.2,
        fuzziness_m: float = 2.0,
    ):
        super().__init__()
        if fuzziness_m <= 1.0:
            raise ValueError("fuzziness_m must be > 1 for Fuzzy C-Means (UFCM)")
        self.n_clusters = n_clusters
        self.latent_dim = latent_dim
        self.fuzziness_m = float(fuzziness_m)

        if hidden_dims is None:
            hidden_dims = [256, 128, 64]

        self.autoencoder = SecurityEventAutoEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout,
        )
        self.cluster_centers = nn.Parameter(
            torch.zeros(n_clusters, latent_dim, dtype=torch.float32)
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.autoencoder.encode(x)

    def squared_distances(self, z: torch.Tensor) -> torch.Tensor:
        """Pairwise squared Euclidean distances between z and cluster centers."""
        diff = z.unsqueeze(1) - self.cluster_centers.unsqueeze(0)
        return (diff * diff).sum(dim=-1)

    def fuzzy_membership(self, z: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Optimal FCM membership u_ik given current centers (standard FCM update),
        differentiable w.r.t. z and cluster_centers.
        Returns (u, squared_distances) both shape [batch, n_clusters].
        """
        sq = self.squared_distances(z)
        dist = torch.sqrt(sq + 1e-8)
        m = self.fuzziness_m
        pow_val = 2.0 / (m - 1.0)
        inv = dist.pow(-pow_val)
        denom = inv.sum(dim=1, keepdim=True).clamp(min=1e-10)
        u = inv / denom
        return u, sq

    def ufcm_objective(self, z: torch.Tensor) -> torch.Tensor:
        """FCM objective J = mean_i sum_k u_ik^m ||z_i - v_k||^2 with optimal u given centers."""
        u, sq = self.fuzzy_membership(z)
        m = self.fuzziness_m
        return (u.pow(m) * sq).sum(dim=1).mean()

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        z, x_recon = self.autoencoder(x)
        u, _ = self.fuzzy_membership(z)
        return u, z, x_recon

    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
        """Initialize cluster centers with K-means on latent codes (same strategy as DEC)."""
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
        kmeans = KMeans(n_clusters=self.n_clusters, n_init=20, random_state=42)
        labels = kmeans.fit_predict(latent_vectors)
        self.cluster_centers.data = torch.tensor(
            kmeans.cluster_centers_, dtype=torch.float32, device=device
        )
        return labels


class DeepMultiViewClustering(nn.Module):
    """
    Deep Multi-View Clustering (DMVC) for security event feature vectors.

    The input is split into two views (first half / second half of features). Each view
    has its own autoencoder; latent codes are fused by averaging, then clustered with the
    same Student-t / KL framework as DEC/IDEC. A multi-view consistency term (MSE between
    view latents) encourages aligned representations across views.
    """

    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: list[int] = None,
        latent_dim: int = 32,
        alpha: float = 1.0,
        dropout: float = 0.2,
    ):
        super().__init__()
        if input_dim < 2:
            raise ValueError("DeepMultiViewClustering requires input_dim >= 2 for two views")
        self.input_dim = input_dim
        self.dim_v1 = input_dim // 2
        self.dim_v2 = input_dim - self.dim_v1
        self.latent_dim = latent_dim
        self.n_clusters = n_clusters

        if hidden_dims is None:
            hidden_dims = [256, 128, 64]

        self.ae1 = SecurityEventAutoEncoder(
            input_dim=self.dim_v1,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout,
        )
        self.ae2 = SecurityEventAutoEncoder(
            input_dim=self.dim_v2,
            hidden_dims=hidden_dims,
            latent_dim=latent_dim,
            dropout=dropout,
        )
        self.clustering_layer = ClusteringLayer(
            n_clusters=n_clusters,
            latent_dim=latent_dim,
            alpha=alpha,
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Fused latent used for visualization and downstream APIs."""
        x1 = x[:, : self.dim_v1]
        x2 = x[:, self.dim_v1 :]
        z1 = self.ae1.encode(x1)
        z2 = self.ae2.encode(x2)
        return 0.5 * (z1 + z2)

    def forward(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        x1 = x[:, : self.dim_v1]
        x2 = x[:, self.dim_v1 :]
        z1, r1 = self.ae1(x1)
        z2, r2 = self.ae2(x2)
        z = 0.5 * (z1 + z2)
        q = self.clustering_layer(z)
        x_recon = torch.cat([r1, r2], dim=1)
        return q, z, x_recon, z1, z2

    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
        """K-means on fused latent codes."""
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
        kmeans = KMeans(n_clusters=self.n_clusters, n_init=20, random_state=42)
        kmeans.fit(latent_vectors)
        self.clustering_layer.cluster_centers.data = torch.tensor(
            kmeans.cluster_centers_, dtype=torch.float32, device=device
        )
        return kmeans.labels_


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
