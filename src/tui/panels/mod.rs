//! Body panels — plain modules with `fn draw(f, app, rect, …)`, dispatched by
//! `Screen` in `super::draw_body`. No trait objects; this is a client, not a
//! framework.

pub mod activity;
pub mod board;
pub mod config_panel;
pub mod doctor;
pub mod help;
pub mod inbox;
pub mod log;
pub mod members;
pub mod peek;
pub mod remotes;
pub mod spaces;
