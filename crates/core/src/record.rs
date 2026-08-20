//! Record-level protection: the traits `#[derive(Protect)]` implements, and
//! the row-key conversion it relies on.
//!
//! The derive lives in `dbsec-derive` and is re-exported as
//! [`crate::Protect`] under the `derive` feature; see its documentation for
//! the attribute grammar. This module is what generated code links against,
//! and what generic code over protected records can name.

use crate::envelope::RowKey;
use crate::policy::Policy;
use crate::protector::Protector;
use crate::Error;

/// A record whose protected fields can be sealed as a unit.
pub trait Protect: Sized {
    /// The same record with every protected field in its stored form.
    type Sealed: Sealed<Record = Self>;
    /// `schema.table` the record lives in.
    const TABLE: &'static str;
    /// The policy the record's declaration describes.
    fn policy() -> Policy;
    /// Seals every protected field, bound to this row when the table
    /// declares a row key.
    fn seal(&self, protector: &Protector) -> Result<Self::Sealed, Error>;
}

/// The stored form of a [`Protect`] record.
pub trait Sealed: Sized {
    /// The record this is the stored form of.
    type Record: Protect<Sealed = Self>;
    /// Opens every protected field. A value that was never sealed is
    /// [`Error::Unprotected`].
    fn open(self, protector: &Protector) -> Result<Self::Record, Error>;
}

/// A `row_key` field's value as the canonical [`RowKey`].
///
/// Implemented for the types PostgreSQL row keys come in. A `uuid::Uuid` is
/// `to_row_key` on its `as_bytes()`; implement the trait for a newtype, or for
/// any other key type, by producing the same bytes the typed
/// [`RowKey`] constructors do.
pub trait ToRowKey {
    /// The canonical row key for this value.
    fn to_row_key(&self) -> Result<RowKey, Error>;
}

impl ToRowKey for i16 {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_i16(*self))
    }
}

impl ToRowKey for i32 {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_i32(*self))
    }
}

impl ToRowKey for i64 {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_i64(*self))
    }
}

impl ToRowKey for str {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_text(self))
    }
}

impl ToRowKey for String {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_text(self))
    }
}

impl ToRowKey for [u8; 16] {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(RowKey::from_uuid_bytes(self))
    }
}

impl ToRowKey for RowKey {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        Ok(self.clone())
    }
}

impl<T: ToRowKey + ?Sized> ToRowKey for &T {
    fn to_row_key(&self) -> Result<RowKey, Error> {
        (**self).to_row_key()
    }
}
