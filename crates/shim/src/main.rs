#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

mod events;
mod exec;
mod io_bridge;
mod sandbox;
mod task;

use task::K7Service;

#[tokio::main]
async fn main() {
    containerd_shim::asynchronous::run::<K7Service>("io.containerd.k7.v1", None).await;
}
