"""
Reinforcement Learning Attack Agent
ใช้ RL เพื่อเรียนรู้และปรับปรุงกลยุทธ์การโจมตีอัตโนมัติ
"""

import numpy as np
import json
import pickle
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import deque
from core.logger import log


class AttackEnvironment:
    """
    Environment สำหรับ RL Agent
    
    State: ข้อมูลเกี่ยวกับ target และ current attack progress
    Action: เลือก attack technique
    Reward: ความสำเร็จของการโจมตี
    """
    
    def __init__(self):
        """Initialize attack environment"""
        self.state = None
        self.episode_history = []
        self.current_episode = []
        
        # Attack techniques (actions)
        self.actions = [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "xxe",
            "ssrf",
            "csrf",
            "auth_bypass",
            "privilege_escalation",
            "rce"
        ]
        
        self.action_space_size = len(self.actions)
        self.state_space_size = 20  # Feature vector size
    
    def reset(self, target_info: Dict[str, Any]) -> np.ndarray:
        """
        Reset environment สำหรับ episode ใหม่
        
        Args:
            target_info: ข้อมูล target
        
        Returns:
            Initial state vector
        """
        self.current_episode = []
        
        # สร้าง state vector จาก target info
        state = self._create_state_vector(target_info)
        self.state = state
        
        return state
    
    def step(self, action_idx: int, result: Dict[str, Any]) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Execute action และรับ reward
        
        Args:
            action_idx: Index ของ action
            result: ผลลัพธ์จากการโจมตี
        
        Returns:
            (next_state, reward, done, info)
        """
        action_name = self.actions[action_idx]
        
        # คำนวณ reward
        reward = self._calculate_reward(result)
        
        # บันทึก transition
        self.current_episode.append({
            "state": self.state.tolist(),
            "action": action_idx,
            "action_name": action_name,
            "reward": reward,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
        # สร้าง next state
        next_state = self._update_state(self.state, action_idx, result)
        self.state = next_state
        
        # ตรวจสอบว่า episode จบหรือยัง
        done = self._is_terminal(result)
        
        # Additional info
        info = {
            "action_name": action_name,
            "vulnerabilities_found": result.get("vulnerabilities_found", 0),
            "success": result.get("success", False)
        }
        
        return next_state, reward, done, info
    
    def _create_state_vector(self, target_info: Dict[str, Any]) -> np.ndarray:
        """
        สร้าง state vector จาก target info
        
        Args:
            target_info: ข้อมูล target
        
        Returns:
            State vector (numpy array)
        """
        # Feature extraction
        features = []
        
        # Technology features (one-hot encoding)
        tech_stack = target_info.get("technology", "").lower()
        features.append(1.0 if "php" in tech_stack else 0.0)
        features.append(1.0 if "python" in tech_stack else 0.0)
        features.append(1.0 if "java" in tech_stack else 0.0)
        features.append(1.0 if "node" in tech_stack else 0.0)
        features.append(1.0 if ".net" in tech_stack else 0.0)
        
        # Database features
        features.append(1.0 if "mysql" in tech_stack else 0.0)
        features.append(1.0 if "postgres" in tech_stack else 0.0)
        features.append(1.0 if "mongodb" in tech_stack else 0.0)
        
        # Web server features
        features.append(1.0 if "apache" in tech_stack else 0.0)
        features.append(1.0 if "nginx" in tech_stack else 0.0)
        
        # Attack progress features
        features.append(target_info.get("vulnerabilities_found", 0) / 10.0)  # Normalized
        features.append(target_info.get("successful_exploits", 0) / 5.0)
        features.append(target_info.get("failed_attempts", 0) / 10.0)
        features.append(1.0 if target_info.get("has_waf", False) else 0.0)
        features.append(1.0 if target_info.get("has_auth", False) else 0.0)
        
        # Previous actions (last 5 actions)
        prev_actions = target_info.get("previous_actions", [])
        for i in range(5):
            if i < len(prev_actions):
                features.append(prev_actions[i] / self.action_space_size)
            else:
                features.append(0.0)
        
        return np.array(features, dtype=np.float32)
    
    def _update_state(self, state: np.ndarray, action_idx: int, result: Dict[str, Any]) -> np.ndarray:
        """
        Update state หลังจาก action
        
        Args:
            state: Current state
            action_idx: Action ที่ทำ
            result: ผลลัพธ์
        
        Returns:
            Updated state
        """
        new_state = state.copy()
        
        # Update attack progress
        new_state[10] += result.get("vulnerabilities_found", 0) / 10.0
        new_state[11] += (1.0 / 5.0) if result.get("success", False) else 0.0
        new_state[12] += (1.0 / 10.0) if not result.get("success", False) else 0.0
        
        # Update previous actions (shift and add new)
        new_state[15:19] = new_state[16:20]
        new_state[19] = action_idx / self.action_space_size
        
        return new_state
    
    def _calculate_reward(self, result: Dict[str, Any]) -> float:
        """
        คำนวณ reward จากผลลัพธ์
        
        Args:
            result: ผลลัพธ์จากการโจมตี
        
        Returns:
            Reward value
        """
        reward = 0.0
        
        # Reward สำหรับหาช่องโหว่
        vulnerabilities_found = result.get("vulnerabilities_found", 0)
        reward += vulnerabilities_found * 10.0
        
        # Reward สำหรับ exploit สำเร็จ
        if result.get("success", False):
            reward += 50.0
        
        # Reward สำหรับ severity
        severity = result.get("severity", "low")
        severity_rewards = {
            "critical": 100.0,
            "high": 50.0,
            "medium": 20.0,
            "low": 5.0
        }
        reward += severity_rewards.get(severity, 0.0)
        
        # Penalty สำหรับความล้มเหลว
        if not result.get("success", False):
            reward -= 5.0
        
        # Penalty สำหรับ WAF detection
        if result.get("waf_detected", False):
            reward -= 20.0
        
        # Penalty สำหรับ rate limiting
        if result.get("rate_limited", False):
            reward -= 15.0
        
        return reward
    
    def _is_terminal(self, result: Dict[str, Any]) -> bool:
        """
        ตรวจสอบว่า episode จบหรือยัง
        
        Args:
            result: ผลลัพธ์จากการโจมตี
        
        Returns:
            True if episode is done
        """
        # จบถ้า exploit สำเร็จ
        if result.get("success", False) and result.get("severity") in ["critical", "high"]:
            return True
        
        # จบถ้าถูก ban
        if result.get("banned", False):
            return True
        
        # จบถ้าทำไปเกิน max steps
        if len(self.current_episode) >= 20:
            return True
        
        return False


class DQNAgent:
    """
    Deep Q-Network Agent สำหรับเรียนรู้กลยุทธ์การโจมตี
    
    ใช้ Q-learning กับ neural network approximation
    """
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.001,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.01
    ):
        """
        Initialize DQN Agent
        
        Args:
            state_size: ขนาดของ state vector
            action_size: จำนวน actions
            learning_rate: Learning rate
            gamma: Discount factor
            epsilon: Exploration rate
            epsilon_decay: Epsilon decay rate
            epsilon_min: Minimum epsilon
        """
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        
        # Experience replay buffer
        self.memory = deque(maxlen=10000)
        self.batch_size = 32
        
        # Q-table (simplified - ในระบบจริงใช้ neural network)
        self.q_table = np.zeros((1000, action_size))  # Simplified state space
        
        # Statistics
        self.total_episodes = 0
        self.total_rewards = []
        self.success_rate = []
    
    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool):
        """
        เก็บ experience ใน replay buffer
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Episode done flag
        """
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state: np.ndarray, explore: bool = True) -> int:
        """
        เลือก action จาก state
        
        Args:
            state: Current state
            explore: Whether to explore or exploit
        
        Returns:
            Action index
        """
        # Epsilon-greedy policy
        if explore and np.random.random() < self.epsilon:
            # Explore: random action
            return np.random.randint(0, self.action_size)
        else:
            # Exploit: best action from Q-table
            state_idx = self._state_to_index(state)
            return np.argmax(self.q_table[state_idx])
    
    def replay(self):
        """
        Train agent จาก experience replay
        """
        if len(self.memory) < self.batch_size:
            return
        
        # Sample batch from memory
        batch = np.random.choice(len(self.memory), self.batch_size, replace=False)
        
        for idx in batch:
            state, action, reward, next_state, done = self.memory[idx]
            
            state_idx = self._state_to_index(state)
            next_state_idx = self._state_to_index(next_state)
            
            # Q-learning update
            target = reward
            if not done:
                target += self.gamma * np.max(self.q_table[next_state_idx])
            
            # Update Q-value
            self.q_table[state_idx][action] += self.learning_rate * (target - self.q_table[state_idx][action])
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def _state_to_index(self, state: np.ndarray) -> int:
        """
        แปลง state vector เป็น index (simplified)
        
        Args:
            state: State vector
        
        Returns:
            State index
        """
        # Simplified hashing
        return int(np.sum(state * 100) % 1000)
    
    def save(self, filepath: str):
        """
        บันทึก model
        
        Args:
            filepath: Path to save file
        """
        model_data = {
            "q_table": self.q_table,
            "epsilon": self.epsilon,
            "total_episodes": self.total_episodes,
            "total_rewards": self.total_rewards,
            "success_rate": self.success_rate
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        log.info(f"[RLAgent] Model saved to {filepath}")
    
    def load(self, filepath: str):
        """
        โหลด model
        
        Args:
            filepath: Path to model file
        """
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.q_table = model_data["q_table"]
            self.epsilon = model_data["epsilon"]
            self.total_episodes = model_data["total_episodes"]
            self.total_rewards = model_data["total_rewards"]
            self.success_rate = model_data["success_rate"]
            
            log.info(f"[RLAgent] Model loaded from {filepath}")
        
        except Exception as e:
            log.error(f"[RLAgent] Failed to load model: {e}")


class RLAttackOrchestrator:
    """
    Orchestrator สำหรับ RL-based attacks
    
    ใช้ RL agent เพื่อเลือก attack techniques อัตโนมัติ
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize RL Attack Orchestrator
        
        Args:
            model_path: Path to pre-trained model (optional)
        """
        self.env = AttackEnvironment()
        self.agent = DQNAgent(
            state_size=self.env.state_space_size,
            action_size=self.env.action_space_size
        )
        
        # Load pre-trained model if provided
        if model_path:
            self.agent.load(model_path)
        
        self.training_mode = False
    
    async def train(self, target_info: Dict[str, Any], num_episodes: int = 100) -> Dict[str, Any]:
        """
        Train RL agent
        
        Args:
            target_info: Target information
            num_episodes: Number of training episodes
        
        Returns:
            Training statistics
        """
        log.info(f"[RLOrchestrator] Starting training for {num_episodes} episodes")
        
        self.training_mode = True
        episode_rewards = []
        success_count = 0
        
        for episode in range(num_episodes):
            state = self.env.reset(target_info)
            episode_reward = 0
            done = False
            steps = 0
            
            while not done and steps < 20:
                # Select action
                action = self.agent.act(state, explore=True)
                action_name = self.env.actions[action]
                
                # Simulate attack result (ในระบบจริงจะเรียก agent จริง)
                result = await self._simulate_attack(action_name, target_info)
                
                # Step environment
                next_state, reward, done, info = self.env.step(action, result)
                
                # Remember experience
                self.agent.remember(state, action, reward, next_state, done)
                
                # Update state
                state = next_state
                episode_reward += reward
                steps += 1
                
                if info.get("success", False):
                    success_count += 1
            
            # Train agent
            self.agent.replay()
            
            # Record statistics
            episode_rewards.append(episode_reward)
            self.agent.total_episodes += 1
            self.agent.total_rewards.append(episode_reward)
            
            if (episode + 1) % 10 == 0:
                avg_reward = np.mean(episode_rewards[-10:])
                log.info(f"[RLOrchestrator] Episode {episode + 1}/{num_episodes}, Avg Reward: {avg_reward:.2f}, Epsilon: {self.agent.epsilon:.3f}")
        
        success_rate = success_count / (num_episodes * 20) * 100
        
        log.success(f"[RLOrchestrator] Training completed. Success rate: {success_rate:.2f}%")
        
        return {
            "num_episodes": num_episodes,
            "total_reward": sum(episode_rewards),
            "avg_reward": np.mean(episode_rewards),
            "success_rate": success_rate,
            "final_epsilon": self.agent.epsilon
        }
    
    async def attack(self, target_info: Dict[str, Any], max_steps: int = 20) -> Dict[str, Any]:
        """
        ใช้ RL agent เพื่อโจมตี
        
        Args:
            target_info: Target information
            max_steps: Maximum attack steps
        
        Returns:
            Attack results
        """
        log.info(f"[RLOrchestrator] Starting RL-based attack")
        
        state = self.env.reset(target_info)
        attack_sequence = []
        total_reward = 0
        done = False
        steps = 0
        
        while not done and steps < max_steps:
            # Select best action (no exploration)
            action = self.agent.act(state, explore=False)
            action_name = self.env.actions[action]
            
            # Execute attack (ในระบบจริงจะเรียก agent จริง)
            result = await self._simulate_attack(action_name, target_info)
            
            # Step environment
            next_state, reward, done, info = self.env.step(action, result)
            
            # Record
            attack_sequence.append({
                "step": steps + 1,
                "action": action_name,
                "reward": reward,
                "success": info.get("success", False),
                "vulnerabilities": info.get("vulnerabilities_found", 0)
            })
            
            state = next_state
            total_reward += reward
            steps += 1
            
            log.info(f"[RLOrchestrator] Step {steps}: {action_name}, Reward: {reward:.2f}")
        
        return {
            "attack_sequence": attack_sequence,
            "total_steps": steps,
            "total_reward": total_reward,
            "success": done and total_reward > 0
        }
    
    async def _simulate_attack(self, action_name: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate attack result (ในระบบจริงจะเรียก agent จริง)
        
        Args:
            action_name: Attack technique name
            target_info: Target information
        
        Returns:
            Attack result
        """
        # Simplified simulation
        success_prob = 0.3
        success = np.random.random() < success_prob
        
        result = {
            "success": success,
            "vulnerabilities_found": np.random.randint(0, 3) if success else 0,
            "severity": np.random.choice(["low", "medium", "high", "critical"]) if success else "low",
            "waf_detected": np.random.random() < 0.1,
            "rate_limited": np.random.random() < 0.05,
            "banned": np.random.random() < 0.01
        }
        
        return result
    
    def save_model(self, filepath: str):
        """
        บันทึก trained model
        
        Args:
            filepath: Path to save file
        """
        self.agent.save(filepath)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        รับสถิติการเรียนรู้
        
        Returns:
            Statistics dictionary
        """
        return {
            "total_episodes": self.agent.total_episodes,
            "avg_reward": np.mean(self.agent.total_rewards) if self.agent.total_rewards else 0,
            "current_epsilon": self.agent.epsilon,
            "memory_size": len(self.agent.memory)
        }


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Initialize RL orchestrator
        rl = RLAttackOrchestrator()
        
        # Target info
        target = {
            "target": "http://localhost:8000",
            "technology": "PHP + MySQL + Apache",
            "vulnerabilities_found": 0,
            "successful_exploits": 0,
            "failed_attempts": 0,
            "has_waf": False,
            "has_auth": True,
            "previous_actions": []
        }
        
        # Train
        print("Training RL agent...")
        train_stats = await rl.train(target, num_episodes=50)
        print(f"Training stats: {train_stats}")
        
        # Save model
        rl.save_model("/tmp/rl_attack_model.pkl")
        
        # Attack
        print("\nExecuting RL-based attack...")
        attack_result = await rl.attack(target, max_steps=10)
        print(f"Attack result: {attack_result}")
        
        # Statistics
        stats = rl.get_statistics()
        print(f"\nStatistics: {stats}")
    
    asyncio.run(main())

