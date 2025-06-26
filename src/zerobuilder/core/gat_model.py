import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv, global_mean_pool
from torch_geometric.data import Data, DataLoader
import os
import pickle
from pathlib import Path
from typing import List, Dict, Optional
import logging
from ..detectors.cpg_parser import RealCPGProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityGAT(torch.nn.Module):
    """
    Graph Attention Network for vulnerability detection in code property graphs.
    Designed to identify patterns across 95+ CWE categories from Juliet dataset.
    """
    def __init__(self, input_dim: int = 128, hidden_dim: int = 256, 
                 num_classes: int = 2, num_heads: int = 8, dropout: float = 0.1):
        super(VulnerabilityGAT, self).__init__()
        
        # Multi-head attention layers
        self.gat1 = GATConv(input_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat2 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat3 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        
        # Classification head
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, num_classes)
        )
        
    def forward(self, x, edge_index, batch=None):
        # Apply GAT layers with residual connections
        h1 = F.elu(self.gat1(x, edge_index))
        h2 = F.elu(self.gat2(h1, edge_index)) + h1  # Residual
        h3 = F.elu(self.gat3(h2, edge_index)) + h2  # Residual
        
        # Global pooling for graph-level prediction
        if batch is not None:
            graph_embedding = global_mean_pool(h3, batch)
        else:
            graph_embedding = torch.mean(h3, dim=0, keepdim=True)
            
        # Classification
        logits = self.classifier(graph_embedding)
        return logits, h3  # Return both prediction and node embeddings

class CPGDataProcessor:
    """
    Processes Joern CPG files into PyTorch Geometric format.
    Handles 95+ CWE categories with proper labeling.
    """
    def __init__(self, cpg_dir: str = "sectestcases"):
        self.cpg_dir = Path(cpg_dir)
        self.cwe_labels = self._load_cwe_mapping()
        
    def _load_cwe_mapping(self) -> Dict[str, int]:
        """Create mapping from CWE categories to vulnerability labels"""
        high_risk_cwes = {
            'CWE121', 'CWE122', 'CWE416', 'CWE415', 'CWE190', 'CWE78',
            'CWE134', 'CWE367', 'CWE366', 'CWE476', 'CWE401', 'CWE590'
        }
        
        cwe_files = list(self.cpg_dir.glob("cpg_CWE*.bin"))
        mapping = {}
        
        for cpg_file in cwe_files:
            cwe_id = cpg_file.stem.split('_')[1]  # Extract CWE123 from cpg_CWE123_...
            if any(high_cwe in cwe_id for high_cwe in high_risk_cwes):
                mapping[cwe_id] = 1  # Vulnerable
            else:
                mapping[cwe_id] = 0  # Benign/Low-risk
                
        logger.info(f"Loaded {len(mapping)} CWE categories: {len([v for v in mapping.values() if v == 1])} high-risk")
        return mapping
    
    def load_cpg_sample(self, cpg_file: Path, max_nodes: int = 1000) -> Optional[Data]:
        """Load a single CPG file and convert to PyG Data object"""
        try:
            # This is a placeholder - actual Joern CPG parsing would require
            # specialized libraries or custom parsing logic
            # For now, create synthetic graph data based on file size
            file_size = cpg_file.stat().st_size
            num_nodes = min(max_nodes, max(10, file_size // 1000))  # Scale with file size
            num_edges = min(num_nodes * 3, file_size // 500)
            
            # Create synthetic node features (in real implementation, extract from CPG)
            x = torch.randn(num_nodes, 128)  # Node features
            
            # Create synthetic edges (in real implementation, extract CFG/DFG edges)
            edge_index = torch.randint(0, num_nodes, (2, num_edges))
            
            # Extract CWE label
            cwe_id = cpg_file.stem.split('_')[1]
            label = self.cwe_labels.get(cwe_id, 0)
            
            return Data(x=x, edge_index=edge_index, y=torch.tensor([label]))
            
        except Exception as e:
            logger.warning(f"Failed to load {cpg_file}: {e}")
            return None
    
    def create_dataset(self, limit: int = 50) -> List[Data]:
        """Create dataset from CPG files"""
        cpg_files = list(self.cpg_dir.glob("cpg_CWE*.bin"))[:limit]
        dataset = []
        
        for cpg_file in cpg_files:
            data = self.load_cpg_sample(cpg_file)
            if data is not None:
                dataset.append(data)
                
        logger.info(f"Created dataset with {len(dataset)} samples")
        return dataset

def train_gat_model(dataset: List[Data], epochs: int = 10):
    """Train GAT model on vulnerability detection task"""
    device = torch.device('cpu')  # CPU-only for now
    
    # Split dataset
    train_size = int(0.8 * len(dataset))
    train_data = dataset[:train_size]
    val_data = dataset[train_size:]
    
    # Create data loaders
    train_loader = DataLoader(train_data, batch_size=8, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=8, shuffle=False)
    
    # Initialize model
    model = VulnerabilityGAT(input_dim=128, hidden_dim=256, num_classes=2).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = torch.nn.CrossEntropyLoss()
    
    logger.info(f"Training GAT model on {len(train_data)} samples, validating on {len(val_data)}")
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0
        train_correct = 0
        train_total = 0
        
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            
            logits, _ = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(logits, batch.y)
            
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            pred = logits.argmax(dim=1)
            train_correct += (pred == batch.y).sum().item()
            train_total += batch.y.size(0)
        
        # Validation
        model.eval()
        val_loss = 0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(device)
                logits, _ = model(batch.x, batch.edge_index, batch.batch)
                loss = criterion(logits, batch.y)
                
                val_loss += loss.item()
                pred = logits.argmax(dim=1)
                val_correct += (pred == batch.y).sum().item()
                val_total += batch.y.size(0)
        
        train_acc = train_correct / train_total
        val_acc = val_correct / val_total
        
        logger.info(f"Epoch {epoch+1}/{epochs}: "
                   f"Train Loss: {train_loss/len(train_loader):.4f}, Train Acc: {train_acc:.4f}, "
                   f"Val Loss: {val_loss/len(val_loader):.4f}, Val Acc: {val_acc:.4f}")
    
    return model

def analyze_vulnerabilities(model, dataset: List[Data]):
    """Analyze vulnerability patterns detected by GAT model"""
    device = torch.device('cpu')
    model.eval()
    
    predictions = []
    attention_weights = []
    
    with torch.no_grad():
        for data in dataset[:10]:  # Analyze first 10 samples
            data = data.to(device)
            logits, node_embeddings = model(data.x, data.edge_index)
            pred = logits.argmax(dim=1).item()
            confidence = F.softmax(logits, dim=1).max().item()
            
            predictions.append({
                'prediction': 'Vulnerable' if pred == 1 else 'Benign',
                'confidence': confidence,
                'true_label': 'Vulnerable' if data.y.item() == 1 else 'Benign'
            })
    
    logger.info("\nVulnerability Analysis Results:")
    for i, pred in enumerate(predictions):
        logger.info(f"Sample {i+1}: {pred['prediction']} (conf: {pred['confidence']:.3f}) "
                   f"| True: {pred['true_label']}")
    
    return predictions

def main():
    """Main GAT pipeline for ZeroBuilder vulnerability detection"""
    logger.info("🚀 Starting ZeroBuilder GAT Pipeline")
    logger.info(f"PyTorch: {torch.__version__}, Device: {'GPU' if torch.cuda.is_available() else 'CPU'}")
    
    try:
        # Load and process CPG data with real parser
        processor = RealCPGProcessor()
        dataset = processor.create_dataset(limit=30)  # Start with 30 samples
        
        if len(dataset) == 0:
            logger.error("No valid CPG data found. Check sectestcases directory.")
            return
        
        # Train GAT model
        model = train_gat_model(dataset, epochs=5)
        
        # Analyze results
        analyze_vulnerabilities(model, dataset)
        
        # Save model
        torch.save(model.state_dict(), 'vulnerability_gat_model.pth')
        logger.info("✅ GAT model saved to vulnerability_gat_model.pth")
        
        logger.info("🎯 ZeroBuilder GAT Pipeline completed successfully!")
        logger.info("Next steps: Integrate with guided fuzzing (Step 1) and RL agents")
        
    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}")
        raise

if __name__ == "__main__":
    main()
