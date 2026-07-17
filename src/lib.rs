//! Shared implementation for the `ops-light-secrets-server` binary.

pub mod clock;
pub mod config;
pub mod control;
pub mod credential;
pub mod identity;
pub mod init;
pub mod input_hygiene;
pub mod proxy;
pub mod raw_target;
pub mod startup;
pub mod storage_executor;
pub mod store;
pub mod transaction_coordinator;
pub mod transport;
