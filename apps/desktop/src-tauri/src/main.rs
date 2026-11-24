// Pas de console sous Windows en version de production.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    messagerie_desktop_lib::run();
}
