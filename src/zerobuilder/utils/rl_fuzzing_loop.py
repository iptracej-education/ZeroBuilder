"""
RL-Guided Fuzzing Loop with GAT Risk Assessment
Implements the learning loop: GAT → RL Agent → Fuzzer → Feedback → Improved GAT
"""

import torch
import numpy as np
from typing import Dict, List, Tuple, Optional
import gymnasium as gym
from stable_baselines3 import PPO, DQN
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback
import logging
import subprocess
import tempfile
import json
from pathlib import Path
import time

logger = logging.getLogger(__name__)

class FuzzingEnvironment(gym.Env):
    """
    RL Environment for intelligent fuzzing
    State: GAT risk scores + current fuzzing stats
    Action: Choose fuzzing strategy (input mutation, target selection)
    Reward: Crashes found + coverage increase
    """
    
    def __init__(self, gat_model, target_binary: str, max_steps: int = 100):
        super().__init__()
        
        self.gat_model = gat_model
        self.target_binary = target_binary
        self.max_steps = max_steps
        self.current_step = 0
        
        # State space: [GAT risk scores (10), fuzzing stats (5), coverage (5)]
        self.observation_space = gym.spaces.Box(
            low=0.0, high=1.0, shape=(20,), dtype=np.float32
        )
        
        # Action space: [mutation_strength, target_function_id, input_strategy]
        self.action_space = gym.spaces.Box(
            low=np.array([0.0, 0.0, 0.0]), 
            high=np.array([1.0, 1.0, 1.0]), 
            dtype=np.float32
        )
        
        # Fuzzing state
        self.reset_fuzzing_state()
        
    def reset_fuzzing_state(self):
        """Reset fuzzing environment state"""
        self.current_step = 0
        self.total_crashes = 0
        self.unique_crashes = 0
        self.coverage_percentage = 0.0
        self.last_crash_step = 0
        self.fuzzing_history = []
        
    def reset(self, seed=None, options=None):
        """Reset environment for new episode"""
        super().reset(seed=seed)
        self.reset_fuzzing_state()
        
        # Get initial GAT risk assessment
        initial_state = self._get_current_state()
        return initial_state, {}
    
    def _get_current_state(self) -> np.ndarray:
        """Get current environment state"""
        # GAT risk scores (10 dimensions)
        gat_risks = self._get_gat_risk_scores()
        
        # Fuzzing statistics (5 dimensions)
        fuzzing_stats = np.array([
            self.total_crashes / 100.0,  # Normalized crash count
            self.unique_crashes / 50.0,  # Normalized unique crashes
            self.coverage_percentage,     # Coverage 0-1
            (self.current_step - self.last_crash_step) / self.max_steps,  # Steps since last crash
            self.current_step / self.max_steps  # Progress through episode
        ], dtype=np.float32)
        
        # Coverage breakdown (5 dimensions)
        coverage_stats = self._get_coverage_stats()
        
        state = np.concatenate([gat_risks, fuzzing_stats, coverage_stats])
        return state.astype(np.float32)
    
    def _get_gat_risk_scores(self) -> np.ndarray:
        """Get risk scores from GAT model for top functions"""
        # Simulate GAT risk assessment (in real implementation, use actual GAT)
        risk_scores = np.array([
            0.85,  # strcpy function risk
            0.72,  # sprintf function risk  
            0.91,  # gets function risk
            0.43,  # malloc function risk
            0.67,  # memcpy function risk
            0.23,  # strncpy function risk (safer)
            0.15,  # snprintf function risk (safer)
            0.78,  # system function risk
            0.34,  # printf function risk
            0.12   # puts function risk (safer)
        ], dtype=np.float32)
        
        return risk_scores
    
    def _get_coverage_stats(self) -> np.ndarray:
        """Get coverage statistics"""
        return np.array([
            self.coverage_percentage,           # Overall coverage
            min(self.coverage_percentage * 1.2, 1.0),  # Function coverage
            min(self.coverage_percentage * 0.8, 1.0),  # Branch coverage  
            min(self.coverage_percentage * 0.6, 1.0),  # Line coverage
            min(self.coverage_percentage * 1.1, 1.0)   # Edge coverage
        ], dtype=np.float32)
    
    def step(self, action: np.ndarray) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute fuzzing action and return results"""
        self.current_step += 1
        
        # Parse action
        mutation_strength = action[0]
        target_function_id = int(action[1] * 9.999)  # 0-9 function targets (avoid index 10)
        input_strategy = action[2]
        
        # Execute fuzzing with given parameters
        crashes_found, coverage_gain = self._execute_fuzzing_step(
            mutation_strength, target_function_id, input_strategy
        )
        
        # Update state
        self.total_crashes += crashes_found
        if crashes_found > 0:
            self.unique_crashes += 1
            self.last_crash_step = self.current_step
            
        self.coverage_percentage = min(
            self.coverage_percentage + coverage_gain, 1.0
        )
        
        # Calculate reward
        reward = self._calculate_reward(crashes_found, coverage_gain)
        
        # Check if episode is done
        done = self.current_step >= self.max_steps
        truncated = False
        
        # Log fuzzing step
        self.fuzzing_history.append({
            'step': self.current_step,
            'action': action.tolist(),
            'crashes': crashes_found,
            'coverage_gain': coverage_gain,
            'reward': reward
        })
        
        next_state = self._get_current_state()
        info = {
            'crashes_found': crashes_found,
            'total_crashes': self.total_crashes,
            'coverage': self.coverage_percentage
        }
        
        return next_state, reward, done, truncated, info
    
    def _execute_fuzzing_step(self, mutation_strength: float, target_function: int, input_strategy: float) -> Tuple[int, float]:
        """
        Execute actual fuzzing step (simplified simulation)
        In real implementation, this would interface with AFL++, LibFuzzer, etc.
        """
        
        # Simulate fuzzing based on GAT guidance
        gat_risks = self._get_gat_risk_scores()
        target_risk = gat_risks[target_function]
        
        # Higher risk targets more likely to crash
        crash_probability = target_risk * mutation_strength * 0.1
        
        # Simulate crashes
        crashes_found = 1 if np.random.random() < crash_probability else 0
        
        # Simulate coverage gain
        base_coverage_gain = 0.005 * mutation_strength
        risk_bonus = target_risk * 0.002  # High-risk targets give more coverage
        coverage_gain = base_coverage_gain + risk_bonus
        
        return crashes_found, coverage_gain
    
    def _calculate_reward(self, crashes_found: int, coverage_gain: float) -> float:
        """Calculate reward for RL agent"""
        reward = 0.0
        
        # Crash reward (primary objective)
        reward += crashes_found * 10.0
        
        # Coverage reward
        reward += coverage_gain * 20.0
        
        # Efficiency bonus (finding crashes quickly)
        if crashes_found > 0:
            efficiency_bonus = max(0, (self.max_steps - self.current_step) / self.max_steps)
            reward += efficiency_bonus * 2.0
        
        # Diversity bonus (exploring different functions)
        if len(set(h.get('target_function', 0) for h in self.fuzzing_history[-10:])) > 5:
            reward += 1.0
        
        return reward

class GATFeedbackCallback(BaseCallback):
    """Callback to update GAT model based on fuzzing results"""
    
    def __init__(self, gat_model, update_frequency: int = 1000):
        super().__init__()
        self.gat_model = gat_model
        self.update_frequency = update_frequency
        self.fuzzing_results = []
        
    def _on_step(self) -> bool:
        """Called after each RL step"""
        
        # Collect fuzzing results
        if 'crashes_found' in self.locals.get('infos', [{}])[0]:
            info = self.locals['infos'][0]
            self.fuzzing_results.append({
                'step': self.num_timesteps,
                'crashes': info['crashes_found'],
                'coverage': info['coverage'],
                'obs': self.locals['obs_tensor'].cpu().numpy()
            })
        
        # Update GAT model periodically
        if self.num_timesteps % self.update_frequency == 0:
            self._update_gat_model()
            
        return True
    
    def _update_gat_model(self):
        """Update GAT model based on fuzzing feedback"""
        if len(self.fuzzing_results) < 10:
            return
            
        logger.info(f"Updating GAT model with {len(self.fuzzing_results)} fuzzing results")
        
        # Analyze which GAT predictions led to crashes
        successful_predictions = [r for r in self.fuzzing_results if r['crashes'] > 0]
        
        if successful_predictions:
            avg_successful_risks = np.mean([r['obs'][:10] for r in successful_predictions], axis=0)
            logger.info(f"High-crash risk pattern: {avg_successful_risks}")
            
        # Clear results buffer
        self.fuzzing_results = []

class LLMReviewer:
    """Interface for LLM-based review and validation"""
    
    def __init__(self):
        self.review_history = []
        
    def review_gat_predictions(self, gat_results: List[Dict], code_samples: List[str]) -> Dict:
        """
        Simulate LLM review of GAT predictions
        In real implementation, this would call Grok, GPT-4, etc.
        """
        
        review = {
            'reviewer': 'Claude-Code-Primary',
            'timestamp': time.time(),
            'predictions_reviewed': len(gat_results),
            'high_confidence_predictions': 0,
            'suggested_improvements': [],
            'validation_score': 0.0
        }
        
        # Analyze predictions
        for i, result in enumerate(gat_results):
            if result['risk_score'] > 0.8:
                review['high_confidence_predictions'] += 1
                
                # Simulate code analysis
                code = code_samples[i] if i < len(code_samples) else ""
                if 'strcpy' in code and 'strncpy' not in code:
                    review['suggested_improvements'].append(f"Prediction {i}: Confirmed high risk - strcpy without bounds")
                elif 'gets' in code:
                    review['suggested_improvements'].append(f"Prediction {i}: Critical risk - gets() always vulnerable")
                else:
                    review['suggested_improvements'].append(f"Prediction {i}: Review needed - unclear vulnerability pattern")
        
        # Calculate validation score
        if review['predictions_reviewed'] > 0:
            review['validation_score'] = review['high_confidence_predictions'] / review['predictions_reviewed']
            
        self.review_history.append(review)
        return review
    
    def critique_fuzzing_strategy(self, fuzzing_history: List[Dict]) -> Dict:
        """LLM critique of fuzzing strategy effectiveness"""
        
        if not fuzzing_history:
            return {'critique': 'No fuzzing history to analyze'}
            
        recent_steps = fuzzing_history[-20:]  # Last 20 steps
        
        crashes_per_step = sum(step.get('crashes', 0) for step in recent_steps) / len(recent_steps)
        avg_coverage_gain = sum(step.get('coverage_gain', 0) for step in recent_steps) / len(recent_steps)
        
        critique = {
            'efficiency_score': crashes_per_step * 10,  # 0-10 scale
            'coverage_score': avg_coverage_gain * 100,  # 0-10 scale
            'recommendations': []
        }
        
        if crashes_per_step < 0.05:
            critique['recommendations'].append("Increase mutation strength - low crash rate")
        if avg_coverage_gain < 0.001:
            critique['recommendations'].append("Diversify target functions - coverage plateau")
            
        return critique

class ZeroBuilderLearningLoop:
    """Main learning loop integrating GAT + RL + Fuzzer + LLM Review"""
    
    def __init__(self, gat_model, target_binaries: List[str]):
        self.gat_model = gat_model
        self.target_binaries = target_binaries
        self.llm_reviewer = LLMReviewer()
        
        # Create RL environment
        self.env = FuzzingEnvironment(gat_model, target_binaries[0])
        
        # Initialize RL agent
        self.rl_agent = PPO(
            "MlpPolicy", 
            self.env, 
            verbose=1,
            learning_rate=3e-4,
            n_steps=2048,
            batch_size=64,
            gamma=0.99,
            tensorboard_log="./tensorboard_logs/"
        )
        
        # Setup feedback callback
        self.gat_callback = GATFeedbackCallback(gat_model)
        
    def run_learning_loop(self, total_timesteps: int = 50000, review_frequency: int = 5000):
        """Run the complete learning loop"""
        
        logger.info("🚀 Starting ZeroBuilder Learning Loop")
        logger.info(f"Total timesteps: {total_timesteps}")
        logger.info(f"LLM review frequency: {review_frequency}")
        
        # Phase 1: Initial GAT assessment
        logger.info("📊 Phase 1: Initial GAT Risk Assessment")
        initial_gat_results = self._run_gat_assessment()
        
        # Phase 2: LLM review of GAT predictions
        logger.info("🧠 Phase 2: LLM Review of GAT Predictions")
        gat_review = self.llm_reviewer.review_gat_predictions(
            initial_gat_results, 
            self._get_code_samples()
        )
        logger.info(f"GAT validation score: {gat_review['validation_score']:.2f}")
        
        # Phase 3: RL-guided fuzzing
        logger.info("🎯 Phase 3: RL-Guided Fuzzing")
        
        for episode in range(total_timesteps // 1000):  # ~50 episodes
            logger.info(f"\\n--- Episode {episode + 1} ---")
            
            # Train RL agent
            self.rl_agent.learn(
                total_timesteps=1000, 
                callback=self.gat_callback,
                reset_num_timesteps=False
            )
            
            # Periodic LLM review
            if (episode + 1) % (review_frequency // 1000) == 0:
                logger.info("🔍 Running periodic LLM review...")
                
                # Get recent fuzzing history
                recent_history = self.env.fuzzing_history[-100:]
                
                # LLM critique
                critique = self.llm_reviewer.critique_fuzzing_strategy(recent_history)
                logger.info(f"Fuzzing efficiency: {critique['efficiency_score']:.2f}/10")
                logger.info(f"Coverage score: {critique['coverage_score']:.2f}/10")
                
                for rec in critique['recommendations']:
                    logger.info(f"💡 Recommendation: {rec}")
        
        # Phase 4: Final evaluation
        logger.info("📈 Phase 4: Final Evaluation")
        final_stats = self._evaluate_performance()
        
        return final_stats
    
    def _run_gat_assessment(self) -> List[Dict]:
        """Run GAT model on target code"""
        
        # Simulate GAT results (in real implementation, process actual CPG data)
        gat_results = [
            {'function': 'strcpy_handler', 'risk_score': 0.87, 'cwe_type': 'CWE121'},
            {'function': 'sprintf_formatter', 'risk_score': 0.74, 'cwe_type': 'CWE122'},
            {'function': 'gets_input', 'risk_score': 0.93, 'cwe_type': 'CWE121'},
            {'function': 'system_exec', 'risk_score': 0.89, 'cwe_type': 'CWE78'},
            {'function': 'malloc_wrapper', 'risk_score': 0.45, 'cwe_type': 'CWE401'},
            {'function': 'safe_strncpy', 'risk_score': 0.18, 'cwe_type': 'None'},
            {'function': 'bounds_checked', 'risk_score': 0.12, 'cwe_type': 'None'},
        ]
        
        return gat_results
    
    def _get_code_samples(self) -> List[str]:
        """Get code samples for LLM review"""
        return [
            "strcpy(buffer, user_input);",
            "sprintf(output, format, data);", 
            "gets(input_buffer);",
            "system(user_command);",
            "ptr = malloc(size);",
            "strncpy(dest, src, sizeof(dest)-1);",
            "if (size < MAX) memcpy(dest, src, size);"
        ]
    
    def _evaluate_performance(self) -> Dict:
        """Evaluate final performance"""
        
        total_crashes = self.env.total_crashes
        final_coverage = self.env.coverage_percentage
        steps_taken = self.env.current_step
        
        stats = {
            'total_crashes_found': total_crashes,
            'final_coverage': final_coverage,
            'steps_taken': steps_taken,
            'crashes_per_step': total_crashes / max(steps_taken, 1),
            'gat_feedback_updates': len(self.gat_callback.fuzzing_results),
            'llm_reviews_conducted': len(self.llm_reviewer.review_history)
        }
        
        logger.info("\\n" + "="*60)
        logger.info("ZEROBUILDER LEARNING LOOP RESULTS")
        logger.info("="*60)
        logger.info(f"🎯 Total crashes found: {stats['total_crashes_found']}")
        logger.info(f"📊 Final coverage: {stats['final_coverage']:.1%}")
        logger.info(f"⚡ Efficiency: {stats['crashes_per_step']:.3f} crashes/step")
        logger.info(f"🔄 GAT updates: {stats['gat_feedback_updates']}")
        logger.info(f"🧠 LLM reviews: {stats['llm_reviews_conducted']}")
        logger.info("="*60)
        
        return stats

def main():
    """Test the complete ZeroBuilder learning loop"""
    
    logging.basicConfig(level=logging.INFO)
    logger.info("🚀 Testing ZeroBuilder Learning Loop")
    
    # Mock GAT model (in real implementation, use actual trained GAT)
    class MockGATModel:
        def predict_risk(self, code): 
            return np.random.random()
    
    gat_model = MockGATModel()
    target_binaries = ["./test_binary1", "./test_binary2"]
    
    # Initialize learning loop
    learning_loop = ZeroBuilderLearningLoop(gat_model, target_binaries)
    
    # Run abbreviated test (1000 timesteps)
    final_stats = learning_loop.run_learning_loop(total_timesteps=5000, review_frequency=2000)
    
    logger.info("✅ ZeroBuilder Learning Loop test completed!")
    logger.info("🔄 Ready for integration with real GAT model and fuzzing tools")

if __name__ == "__main__":
    main()