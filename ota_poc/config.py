"""
Configuration constants for the OTA-POC simulation.

All simulation parameters are centralized here for easy tuning,
reproducibility, and ablation studies. Values are calibrated against
ENISA reports and ISO/SAE 21434 threat modeling baselines.
"""

# --- Beta distribution parameters for stochastic canary fraction ---
# Alpha=50, Beta=4950 gives mean ~0.01 (1%) with realistic variance.
CANARY_BETA_ALPHA: int = 50
CANARY_BETA_BETA: int = 4950

# --- Rollout curve parameters ---
P0_ROLLOUT_HOURS: float = 24.0        # P0/P1: full fleet in 24h (no staging)
P2_CANARY_PHASE_HOURS: float = 6.0    # P2: canary phase duration
P2_POST_CANARY_ROLLOUT_HOURS: float = 48.0  # P2: post-canary gradual rollout

# --- Detection probability scaling ---
DETECTION_SCALING_FACTOR: int = 100   # Divisor for compromised-count scaling

# --- Containment delay (hours) ---
P0_CONTAINMENT_DELAY_HOURS: int = 12
P1_CONTAINMENT_DELAY_HOURS: int = 12
P2_CONTAINMENT_DELAY_HOURS: int = 3

# --- Hourly anomaly detection probability (post-compromise) ---
P0_DETECTION_PROB: float = 0.05
P1_DETECTION_PROB: float = 0.15
P2_DETECTION_PROB: float = 0.90

# --- Pre-install anomaly detection probability ---
# Calibrated against ENISA "Cyber Security Challenges in the Uptake of
# Artificial Intelligence in Autonomous Driving" (2021) Table 4.
P0_PREINSTALL_DETECTION: float = 0.0
P1_PREINSTALL_DETECTION: float = 0.12
P2_PREINSTALL_DETECTION: float = 0.92

# --- CLI defaults ---
DEFAULT_FLEET_SIZE: int = 50000
DEFAULT_RUNS: int = 500
DEFAULT_SEED: int = 42

# --- Convergence check ---
MIN_RUNS_FOR_CONVERGENCE: int = 100
CONVERGENCE_WINDOW: int = 50
CONVERGENCE_THRESHOLD: float = 0.02

# --- Visualization ---
CDF_BINS: int = 30
CDF_DPI: int = 300
CDF_ALPHA: float = 0.9
CDF_LINEWIDTH: int = 2
PLOT_FIGSIZE: tuple[int, int] = (16, 6)
CI_Z_SCORE: float = 1.96

# --- Simulation ---
MAX_SIMULATION_HOURS: int = 144
DEFAULT_VERSION: str = "v1.0"
