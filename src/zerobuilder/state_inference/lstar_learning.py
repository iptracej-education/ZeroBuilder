#!/usr/bin/env python3
"""
ZeroBuilder Step 3: L* Learning Algorithm
Automated state machine inference for protocol analysis
"""

import time
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ObservationTable:
    """L* observation table for state machine learning"""
    states: Set[str] = field(default_factory=set)
    alphabet: Set[str] = field(default_factory=set)
    prefixes: List[str] = field(default_factory=list)
    suffixes: List[str] = field(default_factory=list)
    table: Dict[Tuple[str, str], str] = field(default_factory=dict)
    
    def __post_init__(self):
        # Start with empty string as initial prefix and suffix
        if not self.prefixes:
            self.prefixes = [""]
        if not self.suffixes:
            self.suffixes = [""]

@dataclass
class StateMachine:
    """Learned state machine representation"""
    states: Set[str]
    initial_state: str
    alphabet: Set[str]
    transitions: Dict[Tuple[str, str], str]  # (state, symbol) -> next_state
    outputs: Dict[Tuple[str, str], str]      # (state, symbol) -> output
    
    def process_sequence(self, sequence: List[str]) -> List[str]:
        """Process input sequence and return output sequence"""
        current_state = self.initial_state
        outputs = []
        
        for symbol in sequence:
            if (current_state, symbol) in self.transitions:
                # Get output for this transition
                output = self.outputs.get((current_state, symbol), "")
                outputs.append(output)
                
                # Transition to next state
                current_state = self.transitions[(current_state, symbol)]
            else:
                # Unknown transition - add error output
                outputs.append("ERROR")
                break
        
        return outputs

class LStarLearner:
    """L* algorithm implementation for protocol state machine learning"""
    
    def __init__(self, alphabet: Set[str], oracle_function=None):
        self.alphabet = alphabet
        self.oracle = oracle_function or self._simulate_oracle
        self.observation_table = ObservationTable(alphabet=alphabet)
        self.equivalence_queries = 0
        self.membership_queries = 0
        
        logger.info(f"🔧 L* Learner initialized")
        logger.info(f"📝 Alphabet: {sorted(alphabet)}")
    
    def learn_state_machine(self, max_iterations: int = 20) -> StateMachine:
        """Main L* learning loop"""
        logger.info("🚀 Starting L* state machine learning...")
        
        # Initialize observation table
        self._initialize_table()
        
        iteration = 0
        while iteration < max_iterations:
            logger.info(f"🔄 L* Iteration {iteration + 1}")
            
            # Make table closed and consistent
            self._make_closed()
            self._make_consistent()
            
            # Construct hypothesis automaton
            hypothesis = self._construct_hypothesis()
            
            # Equivalence query
            counterexample = self._equivalence_query(hypothesis)
            
            if counterexample is None:
                logger.info(f"✅ L* learning converged after {iteration + 1} iterations")
                logger.info(f"📊 Final stats: {self.membership_queries} membership queries, {self.equivalence_queries} equivalence queries")
                return hypothesis
            
            # Add counterexample to observation table
            self._add_counterexample(counterexample)
            iteration += 1
        
        logger.warning(f"⚠️ L* learning did not converge within {max_iterations} iterations")
        return self._construct_hypothesis()
    
    def _initialize_table(self):
        """Initialize observation table with empty prefix and suffix"""
        logger.info("🔧 Initializing observation table...")
        
        # Fill initial table entries
        for prefix in self.observation_table.prefixes:
            for suffix in self.observation_table.suffixes:
                sequence = prefix + suffix
                output = self._membership_query(sequence)
                self.observation_table.table[(prefix, suffix)] = output
    
    def _membership_query(self, sequence: str) -> str:
        """Query oracle for output of given input sequence"""
        self.membership_queries += 1
        
        # Convert string sequence to list for oracle
        if sequence == "":
            seq_list = []
        else:
            seq_list = list(sequence)
        
        return self.oracle(seq_list)
    
    def _make_closed(self):
        """Ensure observation table is closed"""
        logger.debug("🔧 Making observation table closed...")
        
        changed = True
        while changed:
            changed = False
            
            # Check if each prefix.symbol has a representative in prefixes
            for prefix in self.observation_table.prefixes[:]:
                for symbol in self.alphabet:
                    extended = prefix + symbol
                    
                    if extended not in self.observation_table.prefixes:
                        # Check if extended has same row as any existing prefix
                        extended_row = self._get_row(extended)
                        
                        found_representative = False
                        for existing_prefix in self.observation_table.prefixes:
                            if self._get_row(existing_prefix) == extended_row:
                                found_representative = True
                                break
                        
                        if not found_representative:
                            # Add extended to prefixes
                            self.observation_table.prefixes.append(extended)
                            
                            # Fill in new table entries
                            for suffix in self.observation_table.suffixes:
                                sequence = extended + suffix
                                output = self._membership_query(sequence)
                                self.observation_table.table[(extended, suffix)] = output
                            
                            changed = True
    
    def _make_consistent(self):
        """Ensure observation table is consistent"""
        logger.debug("🔧 Making observation table consistent...")
        
        changed = True
        while changed:
            changed = False
            
            # Find inconsistent prefixes
            prefixes = self.observation_table.prefixes
            for i in range(len(prefixes)):
                for j in range(i + 1, len(prefixes)):
                    prefix1, prefix2 = prefixes[i], prefixes[j]
                    
                    if self._get_row(prefix1) == self._get_row(prefix2):
                        # Check if prefix1.symbol and prefix2.symbol have same rows for all symbols
                        for symbol in self.alphabet:
                            extended1 = prefix1 + symbol
                            extended2 = prefix2 + symbol
                            
                            if self._get_row(extended1) != self._get_row(extended2):
                                # Found inconsistency - need to add distinguishing suffix
                                distinguishing_suffix = self._find_distinguishing_suffix(extended1, extended2)
                                
                                if distinguishing_suffix not in self.observation_table.suffixes:
                                    self.observation_table.suffixes.append(distinguishing_suffix)
                                    
                                    # Fill in new table entries
                                    for prefix in self.observation_table.prefixes:
                                        sequence = prefix + distinguishing_suffix
                                        output = self._membership_query(sequence)
                                        self.observation_table.table[(prefix, distinguishing_suffix)] = output
                                    
                                    changed = True
                                    break
                        
                        if changed:
                            break
                    
                    if changed:
                        break
    
    def _get_row(self, prefix: str) -> Tuple[str, ...]:
        """Get observation table row for given prefix"""
        row = []
        for suffix in self.observation_table.suffixes:
            output = self.observation_table.table.get((prefix, suffix), "")
            row.append(output)
        return tuple(row)
    
    def _find_distinguishing_suffix(self, seq1: str, seq2: str) -> str:
        """Find suffix that distinguishes between two sequences"""
        # Simple approach: try each symbol
        for symbol in self.alphabet:
            output1 = self._membership_query(seq1 + symbol)
            output2 = self._membership_query(seq2 + symbol)
            
            if output1 != output2:
                return symbol
        
        # If no single symbol distinguishes, try empty suffix
        return ""
    
    def _construct_hypothesis(self) -> StateMachine:
        """Construct hypothesis state machine from observation table"""
        logger.debug("🏗️ Constructing hypothesis state machine...")
        
        # Get unique rows as states
        state_rows = {}
        row_to_state = {}
        state_counter = 0
        
        for prefix in self.observation_table.prefixes:
            row = self._get_row(prefix)
            if row not in row_to_state:
                state_name = f"q{state_counter}"
                row_to_state[row] = state_name
                state_rows[state_name] = row
                state_counter += 1
        
        states = set(state_rows.keys())
        initial_state = row_to_state[self._get_row("")]
        
        # Construct transitions
        transitions = {}
        outputs = {}
        
        for prefix in self.observation_table.prefixes:
            current_state = row_to_state[self._get_row(prefix)]
            
            for symbol in self.alphabet:
                extended = prefix + symbol
                
                # Find which state the extended sequence maps to
                extended_row = self._get_row(extended)
                next_state = row_to_state.get(extended_row)
                
                if next_state:
                    transitions[(current_state, symbol)] = next_state
                    
                    # Get output for this transition
                    output = self.observation_table.table.get((prefix, symbol), "")
                    outputs[(current_state, symbol)] = output
        
        return StateMachine(
            states=states,
            initial_state=initial_state,
            alphabet=self.alphabet,
            transitions=transitions,
            outputs=outputs
        )
    
    def _equivalence_query(self, hypothesis: StateMachine) -> Optional[List[str]]:
        """Check if hypothesis is equivalent to target automaton"""
        self.equivalence_queries += 1
        
        # Simple equivalence check: test random sequences
        test_sequences = self._generate_test_sequences(10)
        
        for sequence in test_sequences:
            # Get expected output from oracle
            expected_output = self.oracle(sequence)
            
            # Get hypothesis output
            hypothesis_output = hypothesis.process_sequence(sequence)
            hypothesis_output_str = "".join(hypothesis_output)
            
            if expected_output != hypothesis_output_str:
                logger.debug(f"🔍 Counterexample found: {sequence}")
                logger.debug(f"   Expected: {expected_output}")
                logger.debug(f"   Got: {hypothesis_output_str}")
                return sequence
        
        return None
    
    def _generate_test_sequences(self, num_sequences: int) -> List[List[str]]:
        """Generate test sequences for equivalence queries"""
        import random
        
        sequences = []
        alphabet_list = list(self.alphabet)
        
        for _ in range(num_sequences):
            length = random.randint(0, 5)
            sequence = [random.choice(alphabet_list) for _ in range(length)]
            sequences.append(sequence)
        
        return sequences
    
    def _add_counterexample(self, counterexample: List[str]):
        """Add counterexample to observation table"""
        logger.debug(f"📝 Adding counterexample: {counterexample}")
        
        # Add all prefixes of counterexample
        for i in range(len(counterexample) + 1):
            prefix = "".join(counterexample[:i])
            
            if prefix not in self.observation_table.prefixes:
                self.observation_table.prefixes.append(prefix)
                
                # Fill in table entries for new prefix
                for suffix in self.observation_table.suffixes:
                    sequence = prefix + suffix
                    output = self._membership_query(sequence)
                    self.observation_table.table[(prefix, suffix)] = output
    
    def _simulate_oracle(self, sequence: List[str]) -> str:
        """Simulate oracle for protocol responses"""
        # Simulate SMB protocol behavior
        if not sequence:
            return "INIT"
        
        # Simple SMB protocol simulation
        state = "INIT"
        outputs = []
        
        for symbol in sequence:
            if state == "INIT":
                if symbol == "NEGOTIATE":
                    state = "NEGOTIATED"
                    outputs.append("OK")
                else:
                    outputs.append("ERROR")
            elif state == "NEGOTIATED":
                if symbol == "SESSION_SETUP":
                    state = "AUTHENTICATED"
                    outputs.append("OK")
                elif symbol == "TREE_CONNECT":
                    outputs.append("ERROR")  # Need auth first
                else:
                    outputs.append("ERROR")
            elif state == "AUTHENTICATED":
                if symbol == "TREE_CONNECT":
                    state = "CONNECTED"
                    outputs.append("OK")
                elif symbol == "SESSION_SETUP":
                    outputs.append("OK")  # Already authenticated
                else:
                    outputs.append("ERROR")
            elif state == "CONNECTED":
                if symbol in ["READ", "WRITE", "CREATE"]:
                    outputs.append("OK")
                elif symbol == "TREE_DISCONNECT":
                    state = "AUTHENTICATED"
                    outputs.append("OK")
                else:
                    outputs.append("ERROR")
        
        return "".join(outputs)

def main():
    """Test L* learning algorithm"""
    logger.info("🚀 Testing L* Learning Algorithm")
    logger.info("Learning SMB protocol state machine")
    logger.info("=" * 60)
    
    # Define SMB protocol alphabet
    smb_alphabet = {
        "NEGOTIATE",
        "SESSION_SETUP", 
        "TREE_CONNECT",
        "TREE_DISCONNECT",
        "CREATE",
        "READ",
        "WRITE",
        "CLOSE"
    }
    
    # Initialize L* learner
    learner = LStarLearner(smb_alphabet)
    
    # Learn state machine
    start_time = time.time()
    learned_machine = learner.learn_state_machine(max_iterations=15)
    learning_time = time.time() - start_time
    
    # Display results
    logger.info(f"\n" + "=" * 60)
    logger.info("📊 L* LEARNING RESULTS")
    logger.info("=" * 60)
    logger.info(f"Learning Time: {learning_time:.2f} seconds")
    logger.info(f"States Learned: {len(learned_machine.states)}")
    logger.info(f"Transitions: {len(learned_machine.transitions)}")
    logger.info(f"Membership Queries: {learner.membership_queries}")
    logger.info(f"Equivalence Queries: {learner.equivalence_queries}")
    
    logger.info(f"\n🏛️ Learned State Machine:")
    logger.info(f"States: {sorted(learned_machine.states)}")
    logger.info(f"Initial State: {learned_machine.initial_state}")
    logger.info(f"Alphabet: {sorted(learned_machine.alphabet)}")
    
    logger.info(f"\n🔄 Transitions:")
    for (state, symbol), next_state in sorted(learned_machine.transitions.items()):
        output = learned_machine.outputs.get((state, symbol), "")
        logger.info(f"  {state} --{symbol}({output})--> {next_state}")
    
    # Test learned machine
    logger.info(f"\n🧪 Testing Learned Machine:")
    test_sequences = [
        ["NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT", "READ"],
        ["SESSION_SETUP"],  # Should fail - need negotiate first
        ["NEGOTIATE", "TREE_CONNECT"],  # Should fail - need auth first
        ["NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT", "WRITE", "TREE_DISCONNECT"]
    ]
    
    for i, sequence in enumerate(test_sequences, 1):
        oracle_output = learner.oracle(sequence)
        machine_output = learned_machine.process_sequence(sequence)
        machine_output_str = "".join(machine_output)
        
        match = "✅" if oracle_output == machine_output_str else "❌"
        logger.info(f"  Test {i}: {match}")
        logger.info(f"    Input: {' -> '.join(sequence)}")
        logger.info(f"    Oracle: {oracle_output}")
        logger.info(f"    Learned: {machine_output_str}")
    
    # Export learned machine
    machine_data = {
        "states": list(learned_machine.states),
        "initial_state": learned_machine.initial_state,
        "alphabet": list(learned_machine.alphabet),
        "transitions": {f"{state},{symbol}": next_state 
                       for (state, symbol), next_state in learned_machine.transitions.items()},
        "outputs": {f"{state},{symbol}": output 
                   for (state, symbol), output in learned_machine.outputs.items()},
        "learning_stats": {
            "learning_time": learning_time,
            "membership_queries": learner.membership_queries,
            "equivalence_queries": learner.equivalence_queries,
            "states_count": len(learned_machine.states),
            "transitions_count": len(learned_machine.transitions)
        }
    }
    
    with open("learned_smb_state_machine.json", "w") as f:
        json.dump(machine_data, f, indent=2)
    
    logger.info(f"\n📁 Learned state machine exported to: learned_smb_state_machine.json")
    logger.info(f"✅ L* learning algorithm test complete!")
    
    return learned_machine

if __name__ == "__main__":
    main()