"""Configuration management via pydantic-settings and chains.yaml."""

from typing import Dict, Optional
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.chains import ChainConfig, load_chains_yaml
from app.risk import RiskConfig, load_risk_config
from app.quality import QualityConfig, load_quality_config


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Simulation flag (must default to False; live pipeline only processes real RPC events)
    simulation_mode: bool = Field(
        default=False,
        description="Enable simulation/dry-run mode (SIMULATION_MODE). Defaults to false.",
    )

    # Multi-chain YAML config path
    chains_config_path: str = Field(
        default="chains.yaml",
        description="Path to multi-chain YAML configuration file",
    )

    # Risk scoring YAML config path
    risk_config_path: str = Field(
        default="risk.yaml",
        description="Path to risk scoring YAML configuration file",
    )

    # Quality scoring YAML config path
    quality_config_path: str = Field(
        default="quality.yaml",
        description="Path to quality scoring and alert tiers YAML configuration file",
    )

    # EVM RPC endpoints (default / single-chain fallback)
    ws_rpc_url: str = Field(
        default="wss://ethereum-rpc.publicnode.com",
        description="WebSocket RPC URL for EVM chain",
    )
    http_rpc_url: Optional[str] = Field(
        default=None,
        description="HTTP RPC URL for EVM calls (falls back to HTTP version of WS_RPC_URL)",
    )

    # Explorer / Etherscan & Blockscout configuration
    etherscan_api_key: Optional[str] = Field(
        default=None,
        description="Etherscan API key for source verification and deployer lookup",
    )
    etherscan_base_url: str = Field(
        default="https://api.etherscan.io/v2/api",
        description="Etherscan API base URL (V2 or V1)",
    )
    blockscout_base_url: str = Field(
        default="https://eth.blockscout.com",
        description="Blockscout base URL for unauthenticated fallback explorer queries",
    )

    # OpenSea API configuration
    opensea_api_key: Optional[str] = Field(
        default=None,
        description="Optional OpenSea v2 API key",
    )
    opensea_base_url: str = Field(
        default="https://api.opensea.io",
        description="OpenSea API base URL",
    )

    # Telegram Bot configuration
    telegram_bot_token: Optional[str] = Field(
        default=None,
        description="Telegram bot token from @BotFather",
    )
    telegram_chat_id: Optional[str] = Field(
        default=None,
        description="Telegram chat ID for alert notifications",
    )

    # Alert Thresholds (All Configurable)
    alert_min_unique_minters: int = Field(
        default=15,
        description="Minimum unique minters required within window to trigger alert",
    )
    alert_window_seconds: int = Field(
        default=300,
        description="Sliding window duration in seconds (default: 300s = 5m)",
    )
    alert_min_mints: int = Field(
        default=15,
        description="Minimum total mints required within window to trigger alert",
    )
    alert_cooldown_seconds: int = Field(
        default=1800,
        description="Cooldown duration before alerting on the same contract again",
    )
    max_contract_age_hours: float = Field(
        default=72.0,
        description="Maximum contract age in hours to be labeled FRESH DEPLOY (MAX_CONTRACT_AGE_HOURS)",
    )
    alert_on_old_contracts: bool = Field(
        default=False,
        description="Whether to send alerts for contracts over MAX_CONTRACT_AGE_HOURS as OLD CONTRACT SURGE (ALERT_ON_OLD_CONTRACTS)",
    )
    realert_after_hours: float = Field(
        default=0.0,
        description="Hours after which to re-alert on an already-alerted contract if a meaningful change occurs (REALERT_AFTER_HOURS, default 0 = never)",
    )
    enrichment_cache_ttl_seconds: int = Field(
        default=600,
        description="SQLite cache TTL in seconds for contract enrichment data",
    )
    enforce_alert_tiers: bool = Field(
        default=False,
        description="Enforce Tier A immediate / Tier B hourly digest / Tier C log-only routing (ENFORCE_ALERT_TIERS)",
    )

    # Database
    sqlite_db_path: str = Field(
        default="data/alerts.db",
        description="Path to SQLite database file",
    )

    # Logging & Observability
    log_level: str = Field(
        default="INFO",
        description="Log level (DEBUG, INFO, WARNING, ERROR)",
    )
    log_file_path: str = Field(
        default="logs/alertbot.log",
        description="Path to rotating log file (LOG_FILE_PATH)",
    )
    heartbeat_interval_hours: float = Field(
        default=6.0,
        description="Telegram heartbeat message interval in hours (HEARTBEAT_INTERVAL_HOURS)",
    )
    healthcheck_url: Optional[str] = Field(
        default=None,
        description="External healthcheck ping URL (HEALTHCHECK_URL)",
    )
    healthcheck_port: int = Field(
        default=8080,
        validation_alias=AliasChoices("HEALTHCHECK_PORT", "PORT", "healthcheck_port"),
        description="Local HTTP health check port (HEALTHCHECK_PORT or Railway PORT)",
    )
    healthcheck_enabled: bool = Field(
        default=True,
        description="Enable local HTTP health check endpoint (HEALTHCHECK_ENABLED)",
    )
    warning_cooldown_seconds: float = Field(
        default=900.0,
        description="Cooldown between duplicate operational Telegram warnings in seconds (WARNING_COOLDOWN_SECONDS)",
    )
    main_loop_watchdog_timeout_seconds: float = Field(
        default=300.0,
        description="Max seconds without completing main loop before exiting for restart (MAIN_LOOP_WATCHDOG_TIMEOUT_SECONDS)",
    )
    chain_watchdog_default_timeout_seconds: float = Field(
        default=60.0,
        description="Default timeout in seconds without new blocks before forcing reconnect (CHAIN_WATCHDOG_DEFAULT_TIMEOUT_SECONDS)",
    )

    @property
    def effective_http_rpc_url(self) -> str:
        """Derive an HTTP RPC URL if not explicitly provided."""
        if self.http_rpc_url:
            return self.http_rpc_url
        if self.ws_rpc_url.startswith("wss://"):
            return "https://" + self.ws_rpc_url[6:]
        if self.ws_rpc_url.startswith("ws://"):
            return "http://" + self.ws_rpc_url[5:]
        return self.ws_rpc_url

    @property
    def is_telegram_mock(self) -> bool:
        """True only when SIMULATION_MODE is explicitly enabled."""
        return bool(self.simulation_mode)

    def get_chains(self, only_enabled: bool = True) -> Dict[str, ChainConfig]:
        """Load configured chains from chains.yaml."""
        return load_chains_yaml(self.chains_config_path, only_enabled=only_enabled)

    def get_risk_config(self) -> RiskConfig:
        """Load configurable risk scoring weights and thresholds from risk.yaml."""
        return load_risk_config(self.risk_config_path)

    def get_quality_config(self) -> QualityConfig:
        """Load configurable quality scoring weights, thresholds, and alert tier rules from quality.yaml."""
        return load_quality_config(self.quality_config_path)


def get_settings() -> Settings:
    """Return a fresh Settings instance."""
    return Settings()
