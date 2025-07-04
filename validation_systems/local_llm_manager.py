#!/usr/bin/env python3
"""
Local Multi-LLM Manager for ZeroBuilder
Manages CodeLlama, StarCoder, and DeepSeek models locally with quantization
"""

import torch
import logging
import time
import gc
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, 
    BitsAndBytesConfig, GenerationConfig
)
from typing import Dict, List, Optional, Any
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LocalLLMManager:
    """Manages local LLM deployment with memory optimization"""
    
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.models = {}
        self.tokenizers = {}
        self.current_model = None
        self.gpu_memory = self._get_gpu_memory()
        
        # Quantization config for 4.3GB GPU
        self.quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )
        
        logger.info(f"🚀 LocalLLMManager initialized")
        logger.info(f"💾 Device: {self.device}")
        logger.info(f"🎯 GPU Memory: {self.gpu_memory:.1f}GB")
        logger.info(f"🔧 Quantization: 4-bit enabled for memory efficiency")
    
    def _get_gpu_memory(self) -> float:
        """Get available GPU memory in GB"""
        if torch.cuda.is_available():
            return torch.cuda.get_device_properties(0).total_memory / 1e9
        return 0.0
    
    def _clear_memory(self):
        """Clear GPU memory"""
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
    
    def load_model(self, model_name: str, model_id: str) -> bool:
        """Load a specific model with memory optimization"""
        try:
            logger.info(f"📥 Loading {model_name}: {model_id}")
            
            # Unload current model to free memory
            if self.current_model and self.current_model != model_name:
                self.unload_current_model()
            
            # Check if already loaded
            if model_name in self.models:
                self.current_model = model_name
                logger.info(f"✅ {model_name} already loaded")
                return True
            
            # Load tokenizer first (lightweight)
            logger.info(f"📝 Loading tokenizer for {model_name}...")
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            # Load model with quantization
            logger.info(f"🧠 Loading model {model_name} with 4-bit quantization...")
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                quantization_config=self.quantization_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            
            # Store model and tokenizer
            self.models[model_name] = model
            self.tokenizers[model_name] = tokenizer
            self.current_model = model_name
            
            # Check memory usage
            if torch.cuda.is_available():
                memory_used = torch.cuda.memory_allocated() / 1e9
                logger.info(f"💾 GPU memory used: {memory_used:.1f}GB / {self.gpu_memory:.1f}GB")
            
            logger.info(f"✅ {model_name} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load {model_name}: {e}")
            self._clear_memory()
            return False
    
    def unload_current_model(self):
        """Unload current model to free memory"""
        if self.current_model and self.current_model in self.models:
            logger.info(f"🗑️ Unloading {self.current_model}")
            del self.models[self.current_model]
            del self.tokenizers[self.current_model]
            self.current_model = None
            self._clear_memory()
    
    def generate_response(self, model_name: str, prompt: str, max_tokens: int = 512) -> str:
        """Generate response using specified model"""
        try:
            # Load model if not current
            if self.current_model != model_name:
                if not self.load_model(model_name, self._get_model_id(model_name)):
                    return f"Error: Failed to load {model_name}"
            
            model = self.models[model_name]
            tokenizer = self.tokenizers[model_name]
            
            # Prepare input
            inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
            inputs = inputs.to(self.device)
            
            # Generation config
            generation_config = GenerationConfig(
                max_new_tokens=max_tokens,
                temperature=0.7,
                do_sample=True,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id
            )
            
            # Generate response
            with torch.no_grad():
                start_time = time.time()
                outputs = model.generate(
                    **inputs,
                    generation_config=generation_config
                )
                generation_time = time.time() - start_time
            
            # Decode response
            response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract only the new generated text
            generated_text = response[len(prompt):].strip()
            
            logger.info(f"⚡ {model_name} response generated in {generation_time:.2f}s")
            return generated_text
            
        except Exception as e:
            logger.error(f"❌ Generation failed for {model_name}: {e}")
            return f"Error: Generation failed - {str(e)}"
    
    def _get_model_id(self, model_name: str) -> str:
        """Get Hugging Face model ID for model name"""
        model_ids = {
            "codellama": "codellama/CodeLlama-7b-Python-hf",
            "starcoder": "bigcode/starcoder2-7b", 
            "deepseek": "deepseek-ai/deepseek-coder-6.7b-instruct"
        }
        return model_ids.get(model_name, model_name)
    
    def test_all_models(self):
        """Test all models with a simple prompt"""
        test_prompt = """
Analyze this code for security vulnerabilities:

```python
def process_user_input(user_data):
    buffer = user_data
    return buffer
```

What security issues do you see?
"""
        
        models_to_test = ["codellama", "starcoder", "deepseek"]
        results = {}
        
        for model_name in models_to_test:
            logger.info(f"\n🧪 Testing {model_name}...")
            
            # Test model loading and generation
            response = self.generate_response(model_name, test_prompt, max_tokens=256)
            results[model_name] = {
                "success": not response.startswith("Error:"),
                "response": response[:200] + "..." if len(response) > 200 else response
            }
            
            logger.info(f"📊 {model_name} result: {'✅ SUCCESS' if results[model_name]['success'] else '❌ FAILED'}")
            if results[model_name]['success']:
                logger.info(f"💬 Sample response: {results[model_name]['response']}")
        
        return results

def main():
    """Test local LLM deployment"""
    logger.info("🚀 Starting Local Multi-LLM Deployment Test")
    logger.info("=" * 60)
    
    # Initialize manager
    llm_manager = LocalLLMManager()
    
    # Test individual model (start with smallest)
    logger.info("\n📋 Phase 1: Testing CodeLlama Python 7B (lightest model)")
    
    success = llm_manager.load_model("codellama", "codellama/CodeLlama-7b-Python-hf")
    
    if success:
        logger.info("✅ CodeLlama loaded successfully!")
        
        # Test generation
        test_prompt = "# Python function to check for buffer overflow vulnerabilities\ndef analyze_buffer_overflow(code):"
        response = llm_manager.generate_response("codellama", test_prompt, max_tokens=128)
        
        logger.info(f"💬 Sample response: {response}")
        logger.info("\n🎉 Local LLM deployment working!")
        logger.info("✅ Ready to deploy other models and integrate with Multi-LLM system")
    else:
        logger.error("❌ CodeLlama deployment failed")
        logger.error("💡 Try: pip install accelerate bitsandbytes")
    
    # Clean up
    llm_manager.unload_current_model()

if __name__ == "__main__":
    main()