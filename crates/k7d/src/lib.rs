//! k7d — purpose-built VM runtime daemon.
//! See for the full specification.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_lossless)]

// `tree_model` is the Aeneas / Charon translation surface for. Under
// `--features verif` everything else is gated out so Charon only sees the pure
// subset.
pub mod tree_model;

#[cfg(not(feature = "verif"))]
pub mod api;
#[cfg(not(feature = "verif"))]
pub mod autowarp;
#[cfg(not(feature = "verif"))]
pub mod block;
#[cfg(not(feature = "verif"))]
pub mod broker;
#[cfg(not(feature = "verif"))]
pub mod cgroup;
#[cfg(not(feature = "verif"))]
pub mod cluster_tree;
#[cfg(not(feature = "verif"))]
pub mod config;
#[cfg(not(feature = "verif"))]
pub mod control;
#[cfg(not(feature = "verif"))]
pub mod devices;
#[cfg(not(feature = "verif"))]
pub mod dilation;
#[cfg(not(feature = "verif"))]
pub mod disks;
#[cfg(not(feature = "verif"))]
pub mod doctor;
#[cfg(not(feature = "verif"))]
pub mod erofs;
#[cfg(not(feature = "verif"))]
pub mod fc;
#[cfg(not(feature = "verif"))]
pub mod fdutil;
#[cfg(not(feature = "verif"))]
pub mod fork;
#[cfg(not(feature = "verif"))]
pub mod guest;
#[cfg(not(feature = "verif"))]
pub mod latency;
#[cfg(not(feature = "verif"))]
pub mod mem_layout;
#[cfg(not(feature = "verif"))]
pub mod mptable;
#[cfg(not(feature = "verif"))]
pub mod netjail;
#[cfg(not(feature = "verif"))]
pub mod netns;
#[cfg(not(feature = "verif"))]
pub mod network;
#[cfg(not(feature = "verif"))]
pub mod pool;
#[cfg(not(feature = "verif"))]
pub mod quickstart;
#[cfg(not(feature = "verif"))]
pub mod seccomp;
#[cfg(not(feature = "verif"))]
pub mod seqmsg;
#[cfg(not(feature = "verif"))]
pub mod snapshot;
#[cfg(not(feature = "verif"))]
pub mod spawner;
#[cfg(not(feature = "verif"))]
pub mod tree;
#[cfg(not(feature = "verif"))]
pub mod virtio_mmio;
#[cfg(not(feature = "verif"))]
pub mod virtiofs;

#[cfg(not(feature = "verif"))]
pub mod vm;
#[cfg(not(feature = "verif"))]
pub mod volumes;
#[cfg(not(feature = "verif"))]
pub mod volumes_blk;
#[cfg(not(feature = "verif"))]
pub mod vsock;
