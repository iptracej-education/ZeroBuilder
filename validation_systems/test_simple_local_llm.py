#!/usr/bin/env python3
"""
Simple test for local LLM deployment
Start with basic functionality before full Multi-LLM integration
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_simple_deployment():
    """Test basic model deployment with error handling"""
    
    logger.info("🔍 Testing Simple Local LLM Deployment")
    logger.info(f"💾 CUDA available: {torch.cuda.is_available()}")
    
    if torch.cuda.is_available():
        logger.info(f"🎯 GPU: {torch.cuda.get_device_properties(0).name}")
        logger.info(f"💾 Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f}GB")
    
    # Start with a very simple quantization approach
    try:
        logger.info("📥 Loading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained("codellama/CodeLlama-7b-Python-hf")
        
        # Set pad token if not exists
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        
        logger.info("✅ Tokenizer loaded successfully")
        
        # Simple quantization config
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16
        )
        
        logger.info("🧠 Loading model with 4-bit quantization...")
        model = AutoModelForCausalLM.from_pretrained(
            "codellama/CodeLlama-7b-Python-hf",
            quantization_config=quant_config,
            device_map="auto",
            torch_dtype=torch.float16
        )
        
        logger.info("✅ Model loaded successfully!")
        
        # Test generation
        test_prompt = "def check_buffer_overflow():"
        logger.info(f"🧪 Testing generation with prompt: {test_prompt}")
        
        inputs = tokenizer(test_prompt, return_tensors="pt")
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=50,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        generated = response[len(test_prompt):].strip()
        
        logger.info(f"✅ Generation successful!")
        logger.info(f"💬 Generated: {generated}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cpu_fallback():
    """Test CPU-only deployment if GPU fails"""
    logger.info("🔄 Testing CPU fallback...")
    
    try:
        tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-small")
        model = AutoModelForCausalLM.from_pretrained("microsoft/DialoGPT-small")
        
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        
        test_prompt = "Hello, how are you?"
        inputs = tokenizer(test_prompt, return_tensors="pt")
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=20,
                pad_token_id=tokenizer.eos_token_id
            )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        logger.info(f"✅ CPU fallback working: {response}")
        return True
        
    except Exception as e:
        logger.error(f"❌ CPU fallback failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("🚀 Starting Local LLM Tests")
    logger.info("=" * 50)
    
    # Test main deployment
    success = test_simple_deployment()
    
    if not success:
        logger.info("🔄 GPU deployment failed, testing CPU fallback...")
        cpu_success = test_cpu_fallback()
        
        if cpu_success:
            logger.info("💡 CPU deployment works - can proceed with CPU-based Multi-LLM")
        else:
            logger.error("❌ Both GPU and CPU deployment failed")
    else:
        logger.info("🎉 GPU deployment successful - ready for Multi-LLM!")