"""
Sequence encoders (LSTM, Transformer) for deep clustering on event windows.

Input: x of shape [batch, seq_len, input_dim] (temporal windows of feature vectors).
The encoder maps a window to a latent z; the decoder reconstructs the **last** vector
in the window (current event), matching the IDEC reconstruction objective.
"""
from __future__ import annotations

import math
from typing import Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.cluster import KMeans

from deep_clustering import BaseAutoEncoder, ClusteringLayer


class PositionalEncoding(nn.Module):
    """Sinusoidal positions for Transformer over time steps."""

    def __init__(self, d_model: int, max_len: int = 2048):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1), :]


class SecurityEventSequenceAutoEncoder(BaseAutoEncoder):
    """
    LSTM or Transformer encoder over [B, T, D]; MLP decoder to reconstruct x[:, -1, :].
    """

    def __init__(
        self,
        input_dim: int,
        seq_len: int,
        seq_hidden: int,
        latent_dim: int,
        encoder_type: str = "lstm",
        dropout: float = 0.2,
        lstm_layers: int = 2,
        transformer_heads: int = 4,
        transformer_layers: int = 2,
    ):
        super().__init__()
        if encoder_type not in ("lstm", "transformer"):
            raise ValueError("encoder_type must be 'lstm' or 'transformer'")
        self.input_dim = input_dim
        self.seq_len = seq_len
        self.seq_hidden = seq_hidden
        self.latent_dim = latent_dim
        self.encoder_type = encoder_type

        self.in_proj = nn.Linear(input_dim, seq_hidden)

        if encoder_type == "lstm":
            self.lstm = nn.LSTM(
                seq_hidden,
                seq_hidden,
                num_layers=lstm_layers,
                batch_first=True,
                dropout=dropout if lstm_layers > 1 else 0.0,
            )
            enc_out_dim = seq_hidden
        else:
            self.pos_enc = PositionalEncoding(seq_hidden, max_len=seq_len + 4)
            layer = nn.TransformerEncoderLayer(
                d_model=seq_hidden,
                nhead=transformer_heads,
                dim_feedforward=seq_hidden * 4,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.transformer = nn.TransformerEncoder(layer, num_layers=transformer_layers)
            enc_out_dim = seq_hidden

        self.fc_z = nn.Linear(enc_out_dim, latent_dim)

        # Decoder: latent -> reconstruct last frame
        dec_hid = max(latent_dim * 2, seq_hidden)
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, dec_hid),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dec_hid, dec_hid // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dec_hid // 2, input_dim),
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """x: [B, T, D] -> z: [B, latent_dim]"""
        h = self.in_proj(x)
        if self.encoder_type == "lstm":
            out, (h_n, _) = self.lstm(h)
            # last layer final hidden
            feat = h_n[-1]
        else:
            h = self.pos_enc(h)
            out = self.transformer(h)
            feat = out.mean(dim=1)
        return self.fc_z(feat)

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encode(x)
        x_recon = self.decode(z)
        return z, x_recon


class DeepEmbeddedClusteringSequence(nn.Module):
    """DEC with sequence autoencoder backbone."""

    def __init__(
        self,
        input_dim: int,
        seq_len: int,
        n_clusters: int,
        seq_hidden: int = 128,
        latent_dim: int = 32,
        alpha: float = 1.0,
        dropout: float = 0.2,
        encoder_type: str = "lstm",
        lstm_layers: int = 2,
        transformer_heads: int = 4,
        transformer_layers: int = 2,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.seq_len = seq_len
        self.latent_dim = latent_dim
        self.n_clusters = n_clusters

        self.autoencoder = SecurityEventSequenceAutoEncoder(
            input_dim=input_dim,
            seq_len=seq_len,
            seq_hidden=seq_hidden,
            latent_dim=latent_dim,
            encoder_type=encoder_type,
            dropout=dropout,
            lstm_layers=lstm_layers,
            transformer_heads=transformer_heads,
            transformer_layers=transformer_layers,
        )
        self.clustering_layer = ClusteringLayer(
            n_clusters=n_clusters,
            latent_dim=latent_dim,
            alpha=alpha,
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.autoencoder.encode(x)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        z, x_recon = self.autoencoder(x)
        q = self.clustering_layer(z)
        return q, z, x_recon

    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
        self.eval()
        latent_vectors = []
        with torch.no_grad():
            for batch in data_loader:
                x = batch[0].to(device)
                z = self.encode(x)
                latent_vectors.append(z.cpu().numpy())
        latent_vectors = np.concatenate(latent_vectors, axis=0)
        kmeans = KMeans(n_clusters=self.n_clusters, n_init=20, random_state=42)
        kmeans.fit(latent_vectors)
        self.clustering_layer.cluster_centers.data = torch.tensor(
            kmeans.cluster_centers_, dtype=torch.float32, device=device
        )
        return kmeans.labels_


class ImprovedDECSequence(nn.Module):
    """IDEC with sequence encoder (LSTM or Transformer)."""

    def __init__(
        self,
        input_dim: int,
        seq_len: int,
        n_clusters: int,
        seq_hidden: int = 128,
        latent_dim: int = 32,
        alpha: float = 1.0,
        gamma: float = 0.1,
        dropout: float = 0.2,
        encoder_type: str = "lstm",
        lstm_layers: int = 2,
        transformer_heads: int = 4,
        transformer_layers: int = 2,
    ):
        super().__init__()
        self.gamma = gamma
        self.dec = DeepEmbeddedClusteringSequence(
            input_dim=input_dim,
            seq_len=seq_len,
            n_clusters=n_clusters,
            seq_hidden=seq_hidden,
            latent_dim=latent_dim,
            alpha=alpha,
            dropout=dropout,
            encoder_type=encoder_type,
            lstm_layers=lstm_layers,
            transformer_heads=transformer_heads,
            transformer_layers=transformer_layers,
        )

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


class DeepUFCMSequence(nn.Module):
    """
    Deep UFCM (fuzzy C-means in latent space) with LSTM sequence encoder over [B, T, D].

    Same UC-FCM-style objective and fuzzy memberships as ``DeepUFCM``, but the encoder is
    ``SecurityEventSequenceAutoEncoder`` (LSTM only); reconstruction targets the **last** frame
    ``x[:, -1, :]`` like sequence IDEC.
    """

    def __init__(
        self,
        input_dim: int,
        seq_len: int,
        n_clusters: int,
        seq_hidden: int = 128,
        latent_dim: int = 32,
        dropout: float = 0.2,
        fuzziness_m: float = 2.0,
        lstm_layers: int = 2,
        transformer_heads: int = 4,
        transformer_layers: int = 2,
    ):
        super().__init__()
        if fuzziness_m <= 1.0:
            raise ValueError("fuzziness_m must be > 1 for Fuzzy C-Means (UFCM)")
        self.n_clusters = n_clusters
        self.latent_dim = latent_dim
        self.fuzziness_m = float(fuzziness_m)

        self.autoencoder = SecurityEventSequenceAutoEncoder(
            input_dim=input_dim,
            seq_len=seq_len,
            seq_hidden=seq_hidden,
            latent_dim=latent_dim,
            encoder_type="lstm",
            dropout=dropout,
            lstm_layers=lstm_layers,
            transformer_heads=transformer_heads,
            transformer_layers=transformer_layers,
        )
        self.cluster_centers = nn.Parameter(
            torch.zeros(n_clusters, latent_dim, dtype=torch.float32)
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.autoencoder.encode(x)

    def squared_distances(self, z: torch.Tensor) -> torch.Tensor:
        diff = z.unsqueeze(1) - self.cluster_centers.unsqueeze(0)
        return (diff * diff).sum(dim=-1)

    def fuzzy_membership(self, z: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        sq = self.squared_distances(z)
        dist = torch.sqrt(sq + 1e-8)
        m = self.fuzziness_m
        pow_val = 2.0 / (m - 1.0)
        inv = dist.pow(-pow_val)
        denom = inv.sum(dim=1, keepdim=True).clamp(min=1e-10)
        u = inv / denom
        return u, sq

    def ufcm_objective(self, z: torch.Tensor) -> torch.Tensor:
        u, sq = self.fuzzy_membership(z)
        m = self.fuzziness_m
        return (u.pow(m) * sq).sum(dim=1).mean()

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        z, x_recon = self.autoencoder(x)
        u, _ = self.fuzzy_membership(z)
        return u, z, x_recon

    def initialize_clusters(self, data_loader: DataLoader, device: torch.device):
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
