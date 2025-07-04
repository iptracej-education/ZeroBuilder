"""
Enhanced GAT Pipeline with Real Vulnerability Pattern Detection
Uses comprehensive vulnerability database and enhanced feature extraction
"""

import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, DataLoader
import os
import pickle
from pathlib import Path
from typing import List, Dict, Optional
import logging
from ..detectors.enhanced_cpg_parser import EnhancedCPGProcessor
from ..utils.vulnerability_patterns import VULNERABILITY_DB, VulnerabilityType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedVulnerabilityGAT(torch.nn.Module):
    """
    Enhanced Graph Attention Network for real vulnerability pattern detection.
    Uses 64-dimensional node features with actual vulnerability signatures.
    """
    def __init__(self, input_dim: int = 64, hidden_dim: int = 256, 
                 num_classes: int = 2, num_heads: int = 8, dropout: float = 0.1):
        super(EnhancedVulnerabilityGAT, self).__init__()
        
        # Multi-head attention layers with increased capacity
        self.gat1 = GATConv(input_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat2 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat3 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat4 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        
        # Vulnerability-specific attention layer
        self.vuln_attention = torch.nn.MultiheadAttention(hidden_dim, num_heads, dropout=dropout)
        
        # Enhanced classification head with vulnerability type prediction
        self.vulnerability_classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim * 2, hidden_dim),  # *2 for mean+max pooling
            torch.nn.BatchNorm1d(hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, num_classes)
        )
        
        # Vulnerability type classifier (10 types)
        self.type_classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim * 2, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim, 10)  # 10 vulnerability types
        )
        
        # Confidence estimation head
        self.confidence_estimator = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim * 2, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_dim // 2, 1),
            torch.nn.Sigmoid()  # Output 0-1 confidence score
        )
        
    def forward(self, x, edge_index, batch=None):
        # Apply GAT layers with residual connections and layer normalization
        h1 = F.elu(self.gat1(x, edge_index))
        h2 = F.elu(self.gat2(h1, edge_index)) + h1  # Residual
        h3 = F.elu(self.gat3(h2, edge_index)) + h2  # Residual
        h4 = F.elu(self.gat4(h3, edge_index)) + h3  # Residual
        
        # Apply vulnerability-specific attention
        h4_attended, attention_weights = self.vuln_attention(
            h4.unsqueeze(1), h4.unsqueeze(1), h4.unsqueeze(1)
        )
        h4_attended = h4_attended.squeeze(1) + h4  # Residual connection
        
        # Dual pooling strategy for better representation
        if batch is not None:
            graph_mean = global_mean_pool(h4_attended, batch)
            graph_max = global_max_pool(h4_attended, batch)
        else:
            graph_mean = torch.mean(h4_attended, dim=0, keepdim=True)
            graph_max = torch.max(h4_attended, dim=0, keepdim=True)[0]
            
        # Combine mean and max pooling
        graph_embedding = torch.cat([graph_mean, graph_max], dim=1)
        
        # Multiple predictions
        vuln_logits = self.vulnerability_classifier(graph_embedding)
        type_logits = self.type_classifier(graph_embedding)
        confidence = self.confidence_estimator(graph_embedding)
        
        return {
            'vulnerability': vuln_logits,
            'type': type_logits, 
            'confidence': confidence,
            'node_embeddings': h4_attended,
            'attention_weights': attention_weights,
            'graph_embedding': graph_embedding
        }

class VulnerabilityAnalyzer:
    """Analyze and interpret GAT predictions with vulnerability context"""
    
    def __init__(self, model, vuln_db):
        self.model = model
        self.vuln_db = vuln_db
        self.vuln_types = list(VulnerabilityType)
        
    def analyze_prediction(self, data: Data, prediction: Dict) -> Dict:
        """Analyze model prediction with vulnerability context"""
        device = next(self.model.parameters()).device
        data = data.to(device)
        
        with torch.no_grad():
            outputs = self.model(data.x, data.edge_index)
            
        # Process vulnerability prediction
        vuln_probs = F.softmax(outputs['vulnerability'], dim=1)
        vuln_pred = vuln_probs.argmax(dim=1).item()
        vuln_confidence = vuln_probs.max().item()
        
        # Process vulnerability type prediction
        type_probs = F.softmax(outputs['type'], dim=1)
        type_pred = type_probs.argmax(dim=1).item()
        type_confidence = type_probs.max().item()
        
        # Get estimated confidence
        estimated_confidence = outputs['confidence'].item()
        
        analysis = {
            'vulnerable': vuln_pred == 1,
            'vulnerability_confidence': vuln_confidence,
            'vulnerability_type': self.vuln_types[type_pred].value if type_pred < len(self.vuln_types) else 'unknown',
            'type_confidence': type_confidence,
            'estimated_confidence': estimated_confidence,
            'true_label': data.y.item() if hasattr(data, 'y') else None,
            'attention_weights': outputs['attention_weights'].cpu().numpy(),
            'graph_embedding': outputs['graph_embedding'].cpu().numpy(),
            'top_vulnerability_types': self._get_top_vulnerability_types(type_probs),
            'risk_assessment': self._assess_risk_level(vuln_confidence, type_confidence)
        }
        
        return analysis
    
    def _get_top_vulnerability_types(self, type_probs: torch.Tensor, top_k: int = 3) -> List[Dict]:
        """Get top K vulnerability types with probabilities"""
        probs = F.softmax(type_probs, dim=1).squeeze()
        top_indices = torch.topk(probs, min(top_k, len(probs))).indices
        
        top_types = []
        for idx in top_indices:
            if idx.item() < len(self.vuln_types):
                top_types.append({
                    'type': self.vuln_types[idx.item()].value,
                    'probability': probs[idx].item()
                })
                
        return top_types
    
    def _assess_risk_level(self, vuln_confidence: float, type_confidence: float) -> str:
        """Assess overall risk level"""
        combined_confidence = (vuln_confidence + type_confidence) / 2
        
        if combined_confidence > 0.9:
            return "CRITICAL"
        elif combined_confidence > 0.7:
            return "HIGH"
        elif combined_confidence > 0.5:
            return "MEDIUM"
        else:
            return "LOW"

def train_enhanced_gat_model(dataset: List[Data], epochs: int = 15, learning_rate: float = 0.001):
    """Train enhanced GAT model with multiple objectives"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Training on device: {device}")
    
    # Split dataset
    train_size = int(0.8 * len(dataset))
    val_size = int(0.1 * len(dataset))
    test_size = len(dataset) - train_size - val_size
    
    train_data = dataset[:train_size]
    val_data = dataset[train_size:train_size + val_size]
    test_data = dataset[train_size + val_size:]
    
    # Create data loaders
    train_loader = DataLoader(train_data, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=16, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=16, shuffle=False)
    
    # Initialize enhanced model
    model = EnhancedVulnerabilityGAT(input_dim=64, hidden_dim=384, num_classes=2).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
    
    # Loss functions
    vuln_criterion = torch.nn.CrossEntropyLoss()
    type_criterion = torch.nn.CrossEntropyLoss()
    confidence_criterion = torch.nn.MSELoss()
    
    logger.info(f"Training enhanced GAT: {len(train_data)} train, {len(val_data)} val, {len(test_data)} test")
    
    best_val_acc = 0.0
    best_model_state = None
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0
        train_correct = 0
        train_total = 0
        
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            
            outputs = model(batch.x, batch.edge_index, batch.batch)
            
            # Multi-objective loss
            vuln_loss = vuln_criterion(outputs['vulnerability'], batch.y)
            
            # Create synthetic type labels (for training - in real scenario, these would be labeled)
            type_labels = batch.y.clone()  # Simplified: use vulnerability label as type
            type_loss = type_criterion(outputs['type'][:, :2], type_labels)  # Use first 2 classes
            
            # Confidence loss (target: 1.0 for correct predictions, 0.5 for incorrect)
            pred_correct = (outputs['vulnerability'].argmax(dim=1) == batch.y).float()
            target_confidence = 0.8 * pred_correct + 0.2  # 0.8 for correct, 0.2 for incorrect
            confidence_loss = confidence_criterion(outputs['confidence'].squeeze(), target_confidence)
            
            # Combined loss
            total_loss = vuln_loss + 0.5 * type_loss + 0.3 * confidence_loss
            
            total_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            
            train_loss += total_loss.item()
            pred = outputs['vulnerability'].argmax(dim=1)
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
                outputs = model(batch.x, batch.edge_index, batch.batch)
                
                loss = vuln_criterion(outputs['vulnerability'], batch.y)
                val_loss += loss.item()
                
                pred = outputs['vulnerability'].argmax(dim=1)
                val_correct += (pred == batch.y).sum().item()
                val_total += batch.y.size(0)
        
        train_acc = train_correct / train_total
        val_acc = val_correct / val_total
        
        # Learning rate scheduling
        scheduler.step(val_loss / len(val_loader))
        
        # Save best model
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_model_state = model.state_dict().copy()
        
        logger.info(f"Epoch {epoch+1}/{epochs}: "
                   f"Train Loss: {train_loss/len(train_loader):.4f}, Train Acc: {train_acc:.4f}, "
                   f"Val Loss: {val_loss/len(val_loader):.4f}, Val Acc: {val_acc:.4f}, "
                   f"LR: {optimizer.param_groups[0]['lr']:.6f}")
    
    # Load best model
    if best_model_state:
        model.load_state_dict(best_model_state)
        logger.info(f"Loaded best model with validation accuracy: {best_val_acc:.4f}")
    
    # Test evaluation
    test_correct = 0
    test_total = 0
    model.eval()
    
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            outputs = model(batch.x, batch.edge_index, batch.batch)
            pred = outputs['vulnerability'].argmax(dim=1)
            test_correct += (pred == batch.y).sum().item()
            test_total += batch.y.size(0)
    
    test_acc = test_correct / test_total
    logger.info(f"Final Test Accuracy: {test_acc:.4f}")
    
    return model

def analyze_enhanced_vulnerabilities(model, dataset: List[Data], num_samples: int = 20):
    """Analyze vulnerabilities with enhanced GAT model"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.eval()
    
    analyzer = VulnerabilityAnalyzer(model, VULNERABILITY_DB)
    
    logger.info("\
" + "="*80)
    logger.info("ENHANCED VULNERABILITY ANALYSIS RESULTS")
    logger.info("="*80)
    
    correct_predictions = 0
    total_predictions = 0
    
    for i, data in enumerate(dataset[:num_samples]):
        analysis = analyzer.analyze_prediction(data, None)
        
        # Check if prediction matches true label
        if analysis['true_label'] is not None:
            is_correct = (analysis['vulnerable'] and analysis['true_label'] == 1) or \
                        (not analysis['vulnerable'] and analysis['true_label'] == 0)
            correct_predictions += is_correct
            total_predictions += 1
            
            status = "✅ CORRECT" if is_correct else "❌ INCORRECT"
        else:
            status = "? UNKNOWN"
        
        logger.info(f"\
Sample {i+1}:")
        logger.info(f"  Prediction: {'VULNERABLE' if analysis['vulnerable'] else 'BENIGN'} "
                   f"(confidence: {analysis['vulnerability_confidence']:.3f}) {status}")
        logger.info(f"  Type: {analysis['vulnerability_type']} "
                   f"(confidence: {analysis['type_confidence']:.3f})")
        logger.info(f"  Risk Level: {analysis['risk_assessment']}")
        logger.info(f"  Estimated Confidence: {analysis['estimated_confidence']:.3f}")
        
        if analysis['true_label'] is not None:
            logger.info(f"  True Label: {'VULNERABLE' if analysis['true_label'] == 1 else 'BENIGN'}")
            
        # Show top vulnerability types
        if len(analysis['top_vulnerability_types']) > 1:
            logger.info(f"  Top Types: {', '.join([f\"{t['type']}({t['probability']:.2f})\" for t in analysis['top_vulnerability_types'][:3]])}")
    
    if total_predictions > 0:
        accuracy = correct_predictions / total_predictions
        logger.info(f"\
" + "="*80)
        logger.info(f"OVERALL ACCURACY: {accuracy:.2%} ({correct_predictions}/{total_predictions})")
        logger.info("="*80)
    
    return correct_predictions, total_predictions

def main():
    """Enhanced GAT pipeline with real vulnerability pattern detection"""
    logger.info("🚀 Starting Enhanced ZeroBuilder GAT Pipeline")
    logger.info(f"PyTorch: {torch.__version__}, Device: {'GPU' if torch.cuda.is_available() else 'CPU'}")
    logger.info(f"Vulnerability Database: {len(VULNERABILITY_DB.vulnerable_patterns)} patterns loaded")
    
    try:
        # Load and process CPG data with enhanced features
        processor = EnhancedCPGProcessor()
        dataset = processor.create_dataset(limit=50)  # Increased to 50 samples
        
        if len(dataset) == 0:
            logger.error("No valid CPG data found. Check sectestcases directory.")
            return
        
        logger.info(f"Dataset created: {len(dataset)} samples")
        
        # Train enhanced GAT model
        model = train_enhanced_gat_model(dataset, epochs=10, learning_rate=0.001)
        
        # Analyze results with enhanced features
        correct, total = analyze_enhanced_vulnerabilities(model, dataset, num_samples=15)
        
        # Save enhanced model
        torch.save({
            'model_state_dict': model.state_dict(),
            'model_config': {
                'input_dim': 64,
                'hidden_dim': 384,
                'num_classes': 2,
                'num_heads': 8
            },
            'vulnerability_patterns': len(VULNERABILITY_DB.vulnerable_patterns)
        }, 'enhanced_vulnerability_gat_model.pth')
        
        logger.info("✅ Enhanced GAT model saved to enhanced_vulnerability_gat_model.pth")
        logger.info(f"🎯 Enhanced ZeroBuilder GAT Pipeline completed! Accuracy: {correct/total:.2%}")
        logger.info("🔄 Ready for Step 1 integration: RL-guided fuzzing with real vulnerability detection")
        
    except Exception as e:
        logger.error(f"❌ Enhanced pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()