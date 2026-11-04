extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_derive(Zeroize, attributes(zeroize))]
pub fn derive_zeroize(_item: TokenStream) -> TokenStream {
    TokenStream::new()
}

#[proc_macro_derive(ZeroizeOnDrop, attributes(zeroize))]
pub fn derive_zeroize_on_drop(_item: TokenStream) -> TokenStream {
    TokenStream::new()
}
