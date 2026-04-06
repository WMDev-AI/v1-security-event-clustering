"""
Graph neural network encoder for deep clustering (IDEC-style).

Uses a dense symmetric k-NN graph within each mini-batch and stacked GCN layers
(A_norm @ h @ W) + MLP decoder. No PyTorch Geometric dependency.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from torch.utils.data import DataLoader
from sklearn.cluster import KMeans
from typing import List, Tuple

from deep_clustering import ClusteringLayer


def symmetric_normalized_knn_adjacency(x: torch.Tensor, k: int) -> torch.Tensor:
    """
    Build symmetric k-NN adjacency with self-loops, then symmetric normalization.
    x: [B, d] -> A_norm: [B, B]
    """
    B = x.size(0)
    if B <= 1:
        return torch.ones(B, B, device=x.device, dtype=x.dtype)

    k_eff = min(max(1, k), B - 1)
    dist = torch.cdist(x, x, p=2.0)
    dist = dist.fill_diagonal_(float("inf"))
    # k smallest distances per row
    _, idx = dist.topk(k_eff, largest=False, dim=1)
    A = torch.zeros(B, B, device=x.device, dtype=x.dtype)
    rows = torch.arange(B, device=x.device).unsqueeze(1).expand(-1, k_eff)
    A[rows, idx] = 1.0
    A = torch.maximum(A, A.t())
    A.fill_diagonal_(1.0)
    deg = A.sum(dim=1).clamp(min=1e-6)
    d_inv_sqrt = deg.pow(-0.5)
    A_norm = d_inv_sqrt.unsqueeze(1) * A * d_inv_sqrt.unsqueeze(0)
    return A_norm


class GNNEncoderDecoder(nn.Module):
    """
    Stacked graph convolutions on batch-induced k-NN graph + feedforward decoder.
    encode(x): [B,d] -> [B,latent_dim]
    """

    def __init__(
        self,
        input_dim: int,
        gnn_hidden_dim: int,
        latent_dim: int,
        n_gnn_layers: int,
        hidden_dims: List[int],
        dropout: float,
        k_neighbors: int,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.k_neighbors = k_neighbors
        self.dropout_p = dropout

        if n_gnn_layers < 1:
            raise ValueError("n_gnn_layers must be >= 1")

        dims = [input_dim] + [gnn_hidden_dim] * (n_gnn_layers - 1) + [latent_dim]
        self.gnn_linears = nn.ModuleList()
        for i in range(len(dims) - 1):
            self.gnn_linears.append(nn.Linear(dims[i], dims[i + 1]))

        # Decoder mirrors SecurityEventAutoEncoder (latent -> input_dim)
        decoder_layers: List[nn.Module] = []
        prev = latent_dim
        for hd in reversed(hidden_dims):
            decoder_layers.extend(
                [
                    nn.Linear(prev, hd),
                    nn.BatchNorm1d(hd),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                ]
            )
            prev = hd
        decoder_layers.append(nn.Linear(prev, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        A = symmetric_normalized_knn_adjacency(x, self.k_neighbors)
        h = x
        for i, lin in enumerate(self.gnn_linears[:-1]):
            h = A @ lin(h)
            h = F.relu(h)
            h = F.dropout(h, p=self.dropout_p, training=self.training)
        z = A @ self.gnn_linears[-1](h)
        return z

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encode(x)
        return z, self.decode(z)


class ImprovedDECGNN(nn.Module):
    """
    Improved DEC with GCN encoder over within-batch k-NN graph (same loss as IDEC).
    """

    def __init__(
        self,
        input_dim: int,
        n_clusters: int,
        hidden_dims: List[int],
        latent_dim: int,
        gnn_hidden_dim: int,
        n_gnn_layers: int,
        k_neighbors: int,
        alpha: float = 1.0,
        gamma: float = 0.1,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.gamma = gamma
        self.n_clusters = n_clusters
        self.latent_dim = latent_dim
        self._ae = GNNEncoderDecoder(
            input_dim=input_dim,
            gnn_hidden_dim=gnn_hidden_dim,
            latent_dim=latent_dim,
            n_gnn_layers=n_gnn_layers,
            hidden_dims=hidden_dims,
            dropout=dropout,
            k_neighbors=k_neighbors,
        )
        self.clustering_layer = ClusteringLayer(
            n_clusters=n_clusters,
            latent_dim=latent_dim,
            alpha=alpha,
        )

    @property
    def autoencoder(self) -> GNNEncoderDecoder:
        return self._ae

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self._ae.encode(x)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        z, x_recon = self._ae(x)
        q = self.clustering_layer(z)
        return q, z, x_recon

    def initialize_clusters(self, data_loader: DataLoader, device: torch.device) -> np.ndarray:
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
            kmeans.cluster_centers_, dtype=torch.float32
        ).to(device)
        return kmeans.labels_
