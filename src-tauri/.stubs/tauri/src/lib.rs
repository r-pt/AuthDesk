pub use tauri_macros::command;

pub struct State<'a, T: 'a>(pub &'a T);

impl<'a, T> std::ops::Deref for State<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
