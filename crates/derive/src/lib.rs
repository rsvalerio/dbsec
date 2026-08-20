//! `#[derive(Protect)]` — declare the protection policy on the struct that
//! holds the data, and get seal / open / search / mask for the whole record.
//!
//! ```ignore
//! use dbsec_core::Protect;
//!
//! #[derive(Protect, Clone)]
//! #[dbsec(table = "public.users", row_key = "id", sealed_derive(Debug, sqlx::FromRow))]
//! struct User {
//!     id: i64,
//!     #[dbsec(searchable)]
//!     email: String,
//!     #[dbsec]
//!     ssn: Option<String>,
//!     #[dbsec(fpe, mask(keep_last = 4))]
//!     phone: String,
//!     notes: String,
//! }
//! ```
//!
//! generates
//!
//! - `UserSealed` — the same fields, with every protected one in its stored
//!   form (`Vec<u8>` for encrypted columns, `String` for FPE and tokens,
//!   `Option` preserved), carrying the derives listed in `sealed_derive`;
//! - `User::TABLE`, `User::policy()` — the `dbsec_core::policy::Policy` the
//!   attributes describe, to build the `Protector` from;
//! - `User::seal(&self, &Protector) -> Result<UserSealed>`;
//! - `UserSealed::open(self, &Protector) -> Result<User>` — refuses a value
//!   that was never sealed — and `open_lenient`, which accepts one;
//! - `User::email_term(&Protector, &[u8]) -> Result<Vec<u8>>` for each
//!   `searchable` field: the blind index to bind to
//!   `substring(email from 1 for 32) = $1`;
//! - `User::masked(&self, &Protector) -> Result<User>` when any field has a
//!   `mask`, with the masks applied;
//! - `impl dbsec_core::record::Protect for User`.
//!
//! Column names default to the field name; `column = "..."` overrides. The
//! `row_key` field's type must implement `dbsec_core::record::ToRowKey`
//! (integers, `String`, `[u8; 16]` out of the box). Protected fields must be
//! `String`, `Vec<u8>`, or `Option` of either.
//!
//! The struct is the single declaration when the application owns the policy.
//! When a TOML policy shared with the proxy is the source of truth instead, the
//! derive still works against a `Protector` built from it — the attributes then
//! only name the fields, and `seal` refuses at runtime if the two disagree on
//! a column's stored form.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned as _;
use syn::{
    parse_macro_input, Data, DeriveInput, Error, Expr, ExprLit, Fields, Ident, Lit, Meta, Path,
    Result, Token, Type,
};

#[proc_macro_derive(Protect, attributes(dbsec))]
pub fn derive_protect(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Encrypt,
    Fpe,
    Token,
    None,
}

struct Mask {
    keep_first: usize,
    keep_last: usize,
    mask_with: char,
}

struct ProtectedField {
    ident: Ident,
    column: String,
    kind: Kind,
    searchable: bool,
    detokenize: bool,
    mask: Option<Mask>,
    shape: Shape,
}

/// What a protected field is declared as, which decides how it is fed to the
/// transform and how the sealed form is typed.
#[derive(Clone, Copy)]
struct Shape {
    optional: bool,
    repr: Repr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Repr {
    Text,
    Bytes,
}

struct StructAttrs {
    table: String,
    row_key: Option<Ident>,
    sealed_derives: Vec<Path>,
}

fn expand(input: DeriveInput) -> Result<Tokens> {
    let name = &input.ident;
    let vis = &input.vis;
    let Data::Struct(data) = &input.data else {
        return Err(Error::new(input.span(), "#[derive(Protect)] only supports structs"));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(Error::new(input.span(), "#[derive(Protect)] needs named fields"));
    };
    let attrs = struct_attrs(&input)?;
    let table = &attrs.table;

    let mut protected = Vec::new();
    let mut plain = Vec::new();
    for field in &fields.named {
        let ident = field.ident.clone().expect("named");
        match field_attrs(field, &ident)? {
            Some(spec) => protected.push(spec),
            None => plain.push((ident, field.ty.clone())),
        }
    }
    if protected.is_empty() {
        return Err(Error::new(
            input.span(),
            "#[derive(Protect)] needs at least one #[dbsec] field",
        ));
    }
    if let Some(row_key) = &attrs.row_key {
        if !plain.iter().any(|(ident, _)| ident == row_key) {
            return Err(Error::new(
                row_key.span(),
                "row_key must name an unprotected field of this struct",
            ));
        }
    }

    let sealed_name = format_ident!("{name}Sealed");
    let sealed_derives = &attrs.sealed_derives;
    let sealed_derive_attr =
        if sealed_derives.is_empty() { quote!() } else { quote!(#[derive(#(#sealed_derives),*)]) };

    // The sealed struct: plain fields as they are, protected ones in stored form.
    let plain_decls = plain.iter().map(|(ident, ty)| quote!(pub #ident: #ty));
    let sealed_decls = protected.iter().map(|f| {
        let ident = &f.ident;
        let ty = f.sealed_type();
        quote!(pub #ident: #ty)
    });

    // Row key expression shared by seal and open.
    let row_expr = match &attrs.row_key {
        Some(key) => quote! {
            let __row = ::core::option::Option::Some(
                ::dbsec_core::record::ToRowKey::to_row_key(&__record.#key)?,
            );
            let __row = __row.as_ref();
        },
        None => {
            quote! { let __row: ::core::option::Option<&::dbsec_core::envelope::RowKey> = ::core::option::Option::None; }
        }
    };

    let plain_moves: Vec<Tokens> =
        plain.iter().map(|(ident, _)| quote!(#ident: __record.#ident)).collect();
    let plain_clones = plain
        .iter()
        .map(|(ident, _)| quote!(#ident: ::core::clone::Clone::clone(&__record.#ident)));

    let seal_fields = protected.iter().map(|f| f.seal_expr(table));
    let open_fields = protected.iter().map(|f| f.open_expr(table, false));
    let open_lenient_fields = protected.iter().map(|f| f.open_expr(table, true));

    let policy_columns = protected.iter().map(|f| f.policy_expr(table));
    let policy_tables = match &attrs.row_key {
        Some(key) => {
            let key = key.to_string();
            quote!(::std::vec![::dbsec_core::policy::TablePolicy::new(#table, #key)])
        }
        None => quote!(::std::vec::Vec::new()),
    };

    let term_fns = protected.iter().filter(|f| f.searchable).map(|f| {
        let fn_name = format_ident!("{}_term", f.ident);
        let column = f.qualified(table);
        let doc = format!(
            "The blind index `{}` is stored under, for `substring({} from 1 for 32) = $1`.",
            f.column, f.column
        );
        quote! {
            #[doc = #doc]
            #vis fn #fn_name(
                protector: &::dbsec_core::protector::Protector,
                plaintext: &[u8],
            ) -> ::core::result::Result<::std::vec::Vec<u8>, ::dbsec_core::Error> {
                protector
                    .search_term(#column, plaintext)?
                    .ok_or_else(|| ::dbsec_core::Error::Policy(::std::format!(
                        "{} is declared searchable on the struct but not in the protector's policy",
                        #column
                    )))
            }
        }
    });

    let masked_fn = if protected.iter().any(|f| f.mask.is_some()) {
        let masks = protected.iter().filter(|f| f.mask.is_some()).map(|f| f.mask_expr(table));
        quote! {
            /// A copy with every `mask`ed field masked for display.
            #vis fn masked(
                &self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<Self, ::dbsec_core::Error>
            where
                Self: ::core::clone::Clone,
            {
                let mut __out = ::core::clone::Clone::clone(self);
                #(#masks)*
                ::core::result::Result::Ok(__out)
            }
        }
    } else {
        quote!()
    };

    Ok(quote! {
        #sealed_derive_attr
        #vis struct #sealed_name {
            #(#plain_decls,)*
            #(#sealed_decls,)*
        }

        impl #name {
            /// `schema.table` this record lives in.
            #vis const TABLE: &'static str = #table;

            /// The policy these attributes declare. Combine with other
            /// records' policies to build one `Protector`.
            #vis fn policy() -> ::dbsec_core::policy::Policy {
                ::dbsec_core::policy::Policy::new(
                    ::std::vec![#(#policy_columns),*],
                    #policy_tables,
                )
            }

            /// Every protected field in its stored form, bound to this row.
            #vis fn seal(
                &self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<#sealed_name, ::dbsec_core::Error> {
                let __record = self;
                #row_expr
                ::core::result::Result::Ok(#sealed_name {
                    #(#plain_clones,)*
                    #(#seal_fields,)*
                })
            }

            #(#term_fns)*

            #masked_fn
        }

        impl #sealed_name {
            /// Opens every protected field. A value that was never sealed is
            /// `Error::Unprotected`; see `open_lenient` to accept one.
            #vis fn open(
                self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<#name, ::dbsec_core::Error> {
                let __record = self;
                #row_expr
                ::core::result::Result::Ok(#name {
                    #(#open_fields,)*
                    #(#plain_moves,)*
                })
            }

            /// Like `open`, but a value that carries none of its column's
            /// stored forms is taken as plaintext — for a table mid-migration.
            #vis fn open_lenient(
                self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<#name, ::dbsec_core::Error> {
                let __record = self;
                #row_expr
                ::core::result::Result::Ok(#name {
                    #(#open_lenient_fields,)*
                    #(#plain_moves,)*
                })
            }
        }

        impl ::dbsec_core::record::Protect for #name {
            type Sealed = #sealed_name;
            const TABLE: &'static str = #table;
            fn policy() -> ::dbsec_core::policy::Policy {
                Self::policy()
            }
            fn seal(
                &self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<Self::Sealed, ::dbsec_core::Error> {
                Self::seal(self, protector)
            }
        }

        impl ::dbsec_core::record::Sealed for #sealed_name {
            type Record = #name;
            fn open(
                self,
                protector: &::dbsec_core::protector::Protector,
            ) -> ::core::result::Result<Self::Record, ::dbsec_core::Error> {
                Self::open(self, protector)
            }
        }
    })
}

impl ProtectedField {
    fn qualified(&self, table: &str) -> String {
        format!("{table}.{}", self.column)
    }

    /// The stored form's Rust type: bytes for envelopes, text for FPE and
    /// tokens, unchanged for a mask-only field.
    fn sealed_type(&self) -> Tokens {
        let inner = match (self.kind, self.shape.repr) {
            (Kind::Encrypt, _) | (Kind::None, Repr::Bytes) => quote!(::std::vec::Vec<u8>),
            (Kind::Fpe | Kind::Token, _) | (Kind::None, Repr::Text) => {
                quote!(::std::string::String)
            }
        };
        if self.shape.optional {
            quote!(::core::option::Option<#inner>)
        } else {
            inner
        }
    }

    fn stored_repr(&self) -> Repr {
        match self.kind {
            Kind::Encrypt => Repr::Bytes,
            Kind::Fpe | Kind::Token => Repr::Text,
            Kind::None => self.shape.repr,
        }
    }

    fn seal_expr(&self, table: &str) -> Tokens {
        let ident = &self.ident;
        let column = self.qualified(table);
        let expected_wire = match self.kind {
            Kind::Encrypt => {
                quote!(::core::option::Option::Some(::dbsec_core::transform::WireForm::Bytea))
            }
            Kind::Fpe | Kind::Token => {
                quote!(::core::option::Option::Some(::dbsec_core::transform::WireForm::Text))
            }
            Kind::None => quote!(::core::option::Option::None),
        };
        let as_bytes = match self.shape.repr {
            Repr::Text => quote!(::core::convert::AsRef::<str>::as_ref(__value).as_bytes()),
            Repr::Bytes => quote!(::core::convert::AsRef::<[u8]>::as_ref(__value)),
        };
        let into_stored = match self.stored_repr() {
            Repr::Bytes => quote!(__sealed),
            Repr::Text => quote!(::std::string::String::from_utf8(__sealed)
                .map_err(|_| ::dbsec_core::Error::Malformed)?),
        };
        let one = quote! {
            {
                if protector.wire(#column)? != #expected_wire {
                    return ::core::result::Result::Err(::dbsec_core::Error::Policy(::std::format!(
                        "{}: the struct and the protector's policy disagree on the stored form",
                        #column
                    )));
                }
                let __sealed = protector.seal(#column, #as_bytes, __row)?;
                #into_stored
            }
        };
        if self.shape.optional {
            quote! {
                #ident: match &__record.#ident {
                    ::core::option::Option::Some(__value) => ::core::option::Option::Some(#one),
                    ::core::option::Option::None => ::core::option::Option::None,
                }
            }
        } else {
            quote! { #ident: { let __value = &__record.#ident; #one } }
        }
    }

    fn open_expr(&self, table: &str, lenient: bool) -> Tokens {
        let ident = &self.ident;
        let column = self.qualified(table);
        // A mask-only column is plaintext at rest by policy: nothing to open,
        // and `Unprotected` would be the wrong word for it.
        if self.kind == Kind::None {
            return quote! { #ident: __record.#ident };
        }
        let stored_bytes = match self.stored_repr() {
            Repr::Text => quote!(__value.as_bytes()),
            Repr::Bytes => quote!(__value.as_slice()),
        };
        let unwrap = if lenient { quote!(.into_bytes()) } else { quote!(.into_value(#column)?) };
        let into_plain = match self.shape.repr {
            Repr::Text => quote!(::std::string::String::from_utf8(__opened)
                .map_err(|_| ::dbsec_core::Error::Malformed)?),
            Repr::Bytes => quote!(__opened),
        };
        let one = quote! {
            {
                let __opened = protector.open(#column, #stored_bytes, __row)? #unwrap;
                #into_plain
            }
        };
        if self.shape.optional {
            quote! {
                #ident: match &__record.#ident {
                    ::core::option::Option::Some(__value) => ::core::option::Option::Some(#one),
                    ::core::option::Option::None => ::core::option::Option::None,
                }
            }
        } else {
            quote! { #ident: { let __value = &__record.#ident; #one } }
        }
    }

    fn mask_expr(&self, table: &str) -> Tokens {
        let ident = &self.ident;
        let column = self.qualified(table);
        let as_bytes = match self.shape.repr {
            Repr::Text => quote!(__value.as_bytes()),
            Repr::Bytes => quote!(__value.as_slice()),
        };
        let back = match self.shape.repr {
            Repr::Text => quote!(::std::string::String::from_utf8(__masked.into_owned())
                .map_err(|_| ::dbsec_core::Error::Malformed)?),
            Repr::Bytes => quote!(__masked.into_owned()),
        };
        let one = quote! {{
            let __masked = protector.mask(#column, #as_bytes)?;
            #back
        }};
        if self.shape.optional {
            quote! {
                if let ::core::option::Option::Some(__value) = &__out.#ident {
                    let __value = #one;
                    __out.#ident = ::core::option::Option::Some(__value);
                }
            }
        } else {
            quote! {
                {
                    let __value = &__out.#ident;
                    let __value = #one;
                    __out.#ident = __value;
                }
            }
        }
    }

    fn policy_expr(&self, table: &str) -> Tokens {
        let column = &self.column;
        let kind = match self.kind {
            Kind::Encrypt => quote!(::dbsec_core::policy::TransformKind::Encrypt),
            Kind::Fpe => quote!(::dbsec_core::policy::TransformKind::Fpe),
            Kind::Token => quote!(::dbsec_core::policy::TransformKind::Token),
            Kind::None => quote!(::dbsec_core::policy::TransformKind::None),
        };
        let searchable = self.searchable;
        let detokenize = self.detokenize;
        let mask = match &self.mask {
            Some(Mask { keep_first, keep_last, mask_with }) => quote! {
                .mask(::dbsec_core::mask::MaskSpec {
                    keep_first: #keep_first,
                    keep_last: #keep_last,
                    mask_with: #mask_with,
                })
            },
            None => quote!(),
        };
        quote! {
            ::dbsec_core::policy::ColumnPolicy::new(#table, #column)
                .transform(#kind)
                .searchable(#searchable)
                .detokenize(#detokenize)
                #mask
        }
    }
}

// ---- attribute parsing -----------------------------------------------------

fn struct_attrs(input: &DeriveInput) -> Result<StructAttrs> {
    let mut table = None;
    let mut row_key = None;
    let mut sealed_derives = Vec::new();
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("dbsec")) {
        let metas = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        for meta in metas {
            match &meta {
                Meta::NameValue(nv) if nv.path.is_ident("table") => {
                    table = Some(string_lit(&nv.value, "table")?);
                }
                Meta::NameValue(nv) if nv.path.is_ident("row_key") => {
                    let name = string_lit(&nv.value, "row_key")?;
                    row_key = Some(Ident::new(&name, nv.value.span()));
                }
                Meta::List(list) if list.path.is_ident("sealed_derive") => {
                    let paths =
                        list.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)?;
                    sealed_derives.extend(paths);
                }
                other => {
                    return Err(Error::new(
                        other.span(),
                        "expected `table = \"...\"`, `row_key = \"field\"` or `sealed_derive(...)`",
                    ))
                }
            }
        }
    }
    let table = table.ok_or_else(|| {
        Error::new(
            input.ident.span(),
            "#[derive(Protect)] needs #[dbsec(table = \"schema.table\")]",
        )
    })?;
    let table = match table.split_once('.') {
        Some(_) => table,
        None => format!("public.{table}"),
    };
    Ok(StructAttrs { table, row_key, sealed_derives })
}

/// `None` when the field carries no `#[dbsec]` attribute.
fn field_attrs(field: &syn::Field, ident: &Ident) -> Result<Option<ProtectedField>> {
    let attrs: Vec<_> = field.attrs.iter().filter(|a| a.path().is_ident("dbsec")).collect();
    if attrs.is_empty() {
        return Ok(None);
    }
    let mut spec = ProtectedField {
        ident: ident.clone(),
        column: ident.to_string(),
        kind: Kind::Encrypt,
        searchable: false,
        detokenize: true,
        mask: None,
        shape: shape_of(&field.ty)?,
    };
    for attr in attrs {
        // Bare `#[dbsec]` is the encrypt default.
        if matches!(attr.meta, Meta::Path(_)) {
            continue;
        }
        let metas = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        for meta in metas {
            match &meta {
                Meta::Path(p) if p.is_ident("encrypt") => spec.kind = Kind::Encrypt,
                Meta::Path(p) if p.is_ident("fpe") => spec.kind = Kind::Fpe,
                Meta::Path(p) if p.is_ident("token") => spec.kind = Kind::Token,
                Meta::Path(p) if p.is_ident("none") => spec.kind = Kind::None,
                Meta::Path(p) if p.is_ident("searchable") => spec.searchable = true,
                Meta::NameValue(nv) if nv.path.is_ident("searchable") => {
                    spec.searchable = bool_lit(&nv.value, "searchable")?;
                }
                Meta::NameValue(nv) if nv.path.is_ident("detokenize") => {
                    spec.detokenize = bool_lit(&nv.value, "detokenize")?;
                }
                Meta::NameValue(nv) if nv.path.is_ident("column") => {
                    spec.column = string_lit(&nv.value, "column")?;
                }
                Meta::List(list) if list.path.is_ident("mask") => {
                    spec.mask = Some(list.parse_args::<MaskArgs>()?.0);
                }
                Meta::Path(p) if p.is_ident("mask") => {
                    spec.mask = Some(Mask { keep_first: 0, keep_last: 0, mask_with: '*' });
                }
                other => return Err(Error::new(
                    other.span(),
                    "expected one of: encrypt, fpe, token, none, searchable, detokenize = bool, \
                         column = \"...\", mask(keep_first = N, keep_last = N, mask_with = 'c')",
                )),
            }
        }
    }
    Ok(Some(spec))
}

struct MaskArgs(Mask);

impl Parse for MaskArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut mask = Mask { keep_first: 0, keep_last: 0, mask_with: '*' };
        let metas = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;
        for meta in metas {
            let Meta::NameValue(nv) = &meta else {
                return Err(Error::new(
                    meta.span(),
                    "expected `keep_first = N`, `keep_last = N` or `mask_with = 'c'`",
                ));
            };
            if nv.path.is_ident("keep_first") {
                mask.keep_first = int_lit(&nv.value, "keep_first")?;
            } else if nv.path.is_ident("keep_last") {
                mask.keep_last = int_lit(&nv.value, "keep_last")?;
            } else if nv.path.is_ident("mask_with") {
                mask.mask_with = char_lit(&nv.value, "mask_with")?;
            } else {
                return Err(Error::new(
                    nv.path.span(),
                    "expected keep_first, keep_last or mask_with",
                ));
            }
        }
        Ok(Self(mask))
    }
}

/// `String`, `Vec<u8>`, `Option<String>` or `Option<Vec<u8>>` — judged by the
/// type's last path segment, which is what a derive can see.
fn shape_of(ty: &Type) -> Result<Shape> {
    let err = || {
        Error::new(
            ty.span(),
            "a #[dbsec] field must be String, Vec<u8>, Option<String> or Option<Vec<u8>>",
        )
    };
    let Type::Path(path) = ty else { return Err(err()) };
    let segment = path.path.segments.last().ok_or_else(err)?;
    match segment.ident.to_string().as_str() {
        "String" => Ok(Shape { optional: false, repr: Repr::Text }),
        "Vec" => Ok(Shape { optional: false, repr: Repr::Bytes }),
        "Option" => {
            let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
                return Err(err());
            };
            let Some(syn::GenericArgument::Type(inner)) = args.args.first() else {
                return Err(err());
            };
            let inner = shape_of(inner)?;
            if inner.optional {
                return Err(err());
            }
            Ok(Shape { optional: true, repr: inner.repr })
        }
        _ => Err(err()),
    }
}

fn string_lit(expr: &Expr, what: &str) -> Result<String> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => Ok(s.value()),
        other => Err(Error::new(other.span(), format!("{what} expects a string literal"))),
    }
}

fn bool_lit(expr: &Expr, what: &str) -> Result<bool> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Bool(b), .. }) => Ok(b.value),
        other => Err(Error::new(other.span(), format!("{what} expects true or false"))),
    }
}

fn int_lit(expr: &Expr, what: &str) -> Result<usize> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => i.base10_parse(),
        other => Err(Error::new(other.span(), format!("{what} expects an integer literal"))),
    }
}

fn char_lit(expr: &Expr, what: &str) -> Result<char> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Char(c), .. }) => Ok(c.value()),
        other => Err(Error::new(other.span(), format!("{what} expects a char literal"))),
    }
}
