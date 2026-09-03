//! Create cell types.

use std::fmt::{Debug, Formatter, Result as FmtResult, from_fn};
use std::num::NonZeroU32;

use base64ct::{Base64Unpadded, Encoding};
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, ZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};
use crate::utils::encoded_len;

/// `CREATE2` cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Create2Data {
    ty: U16,
    len: U16,
    data: [u8; const { FIXED_CELL_SIZE - 4 }],
}

/// `CREATE2` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/create-created-cells.html#CREATE).
pub struct Create2 {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for Create2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Create2")
            .field("circuit", &self.circuit)
            .field("handshake_ty", &self.handshake_ty())
            .field(
                "payload",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(FIXED_CELL_SIZE - 4);
                    let mut a = [0u8; LEN];
                    let s = self.payload();
                    let o = &mut a[..encoded_len(s.len())];
                    let out = Base64Unpadded::encode(s, o).expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .finish()
    }
}

impl TryFromCell for Create2 {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            let data: &Create2Data = transmute_ref!(cell.data().data());
            if data.len.get() as usize <= FIXED_CELL_SIZE - 4 {
                Ok(Some(Self {
                    circuit,
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Create2> for Cell {
    #[inline]
    fn from(cell: Create2) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Create2::ID,
                circuit: cell.circuit.into(),
            },
            cell.into_inner(),
        )
    }
}

impl From<Create2> for FixedCell {
    #[inline]
    fn from(v: Create2) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Create2 {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl Create2 {
    /// Cell ID of `CREATE2`.
    pub const ID: u8 = 10;

    /// Creates new [`Create2`].
    ///
    /// Returns [`None`] if payload does not fit the cell.
    #[must_use]
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, ty: u16, data: &[u8]) -> Option<Self> {
        if data.len() > FIXED_CELL_SIZE - 4 {
            return None;
        }

        let p: &mut Create2Data = transmute_mut!(cell.data_mut());
        p.ty.set(ty);
        p.len.set(data.len() as u16);
        let (a, b) = p.data.split_at_mut(data.len());
        a.copy_from_slice(data);
        b.fill(0);

        Some(Self { circuit, cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    #[inline]
    fn get_ref(&self) -> &Create2Data {
        transmute_ref!(self.cell.data())
    }

    #[inline]
    fn get_mut(&mut self) -> &mut Create2Data {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets handshake type.
    #[inline]
    #[must_use]
    pub fn handshake_ty(&self) -> u16 {
        self.get_ref().ty.get()
    }

    /// Sets handshake type.
    #[inline]
    pub fn set_handshake_ty(&mut self, ty: u16) {
        self.get_mut().ty.set(ty);
    }

    /// Gets reference to payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let cell = self.get_ref();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked(..cell.len.get() as usize) }
    }

    /// Gets mutable reference to payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let cell = self.get_mut();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked_mut(..cell.len.get() as usize) }
    }

    /// Gets payload length.
    ///
    /// Guaranteed to be <= [`FIXED_CELL_SIZE`] - 4 and equals to returned [`Self::payload`] slice length.
    #[inline]
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.get_ref().len.get().into()
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `CREATED2` cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Created2Data {
    len: U16,
    data: [u8; const { FIXED_CELL_SIZE - 2 }],
}

/// `CREATED2` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/create-created-cells.html#CREATE).
pub struct Created2 {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for Created2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Created2")
            .field("circuit", &self.circuit)
            .field(
                "payload",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(FIXED_CELL_SIZE - 2);
                    let mut a = [0u8; LEN];
                    let s = self.payload();
                    let o = &mut a[..encoded_len(s.len())];
                    let out = Base64Unpadded::encode(s, o).expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .finish()
    }
}

impl TryFromCell for Created2 {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            let data: &Created2Data = transmute_ref!(cell.data().data());
            if data.len.get() as usize <= FIXED_CELL_SIZE - 2 {
                Ok(Some(Self {
                    circuit,
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Created2> for Cell {
    #[inline]
    fn from(cell: Created2) -> Self {
        Self::from_fixed(
            CellHeader {
                command: Created2::ID,
                circuit: cell.circuit.into(),
            },
            cell.into_inner(),
        )
    }
}

impl From<Created2> for FixedCell {
    #[inline]
    fn from(v: Created2) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for Created2 {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl Created2 {
    /// Cell ID of `CREATED2`.
    pub const ID: u8 = 11;

    /// Creates new [`Created2`].
    ///
    /// Returns [`None`] if payload does not fit the cell.
    #[must_use]
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, data: &[u8]) -> Option<Self> {
        if data.len() > FIXED_CELL_SIZE - 2 {
            return None;
        }

        let p: &mut Created2Data = transmute_mut!(cell.data_mut());
        p.len.set(data.len() as u16);
        let (a, b) = p.data.split_at_mut(data.len());
        a.copy_from_slice(data);
        b.fill(0);

        Some(Self { circuit, cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    #[inline]
    fn get_ref(&self) -> &Created2Data {
        transmute_ref!(self.cell.data())
    }

    #[inline]
    fn get_mut(&mut self) -> &mut Created2Data {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets reference to payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let cell = self.get_ref();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked(..cell.len.get() as usize) }
    }

    /// Gets mutable reference to payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let cell = self.get_mut();
        // SAFETY: Length field is validated.
        unsafe { cell.data.get_unchecked_mut(..cell.len.get() as usize) }
    }

    /// Gets payload length.
    ///
    /// Guaranteed to be <= [`FIXED_CELL_SIZE`] - 2 and equals to returned [`Self::payload`] slice length.
    #[inline]
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.get_ref().len.get().into()
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `CREATE_FAST` cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CreateFastData {
    x: [u8; 20],
    padding: [u8; const { FIXED_CELL_SIZE - 20 }],
}

/// `CREATE_FAST` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/create-created-cells.html#create_fast).
pub struct CreateFast {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for CreateFast {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("CreateFast")
            .field("circuit", &self.circuit)
            .field(
                "x",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(20);
                    let mut a = [0u8; LEN];
                    let out = Base64Unpadded::encode(self.x(), &mut a)
                        .expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .finish()
    }
}

impl TryFromCell for CreateFast {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            Ok(Some(Self {
                circuit,
                cell: cell.into_inner().1,
            }))
        } else {
            Ok(None)
        }
    }
}

impl From<CreateFast> for Cell {
    #[inline]
    fn from(cell: CreateFast) -> Self {
        Self::from_fixed(
            CellHeader {
                command: CreateFast::ID,
                circuit: cell.circuit.into(),
            },
            cell.into_inner(),
        )
    }
}

impl From<CreateFast> for FixedCell {
    #[inline]
    fn from(v: CreateFast) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for CreateFast {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl CreateFast {
    /// Cell ID of `CREATE_FAST`.
    pub const ID: u8 = 5;

    /// Creates new [`CreateFast`].
    #[must_use]
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, x: [u8; 20]) -> Self {
        let p: &mut CreateFastData = transmute_mut!(cell.data_mut());
        p.x = x;
        p.padding.fill(0);

        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    #[inline]
    fn get_ref(&self) -> &CreateFastData {
        transmute_ref!(self.cell.data())
    }

    #[inline]
    fn get_mut(&mut self) -> &mut CreateFastData {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets reference to key data.
    #[inline]
    #[must_use]
    pub fn x(&self) -> &[u8; 20] {
        &self.get_ref().x
    }

    /// Gets mutable reference to key data.
    #[inline]
    pub fn x_mut(&mut self) -> &mut [u8; 20] {
        &mut self.get_mut().x
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}

/// `CREATED_FAST` cell data.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CreatedFastData {
    y: [u8; 20],
    derived: [u8; 20],
    padding: [u8; const { FIXED_CELL_SIZE - 20 * 2 }],
}

/// `CREATED_FAST` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/create-created-cells.html#create_fast).
pub struct CreatedFast {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for CreatedFast {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("CreatedFast")
            .field("circuit", &self.circuit)
            .field(
                "y",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(20);
                    let mut a = [0u8; LEN];
                    let out = Base64Unpadded::encode(self.y(), &mut a)
                        .expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .field(
                "derived",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(20);
                    let mut a = [0u8; LEN];
                    let out = Base64Unpadded::encode(self.derived(), &mut a)
                        .expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .finish()
    }
}

impl TryFromCell for CreatedFast {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            Ok(Some(Self {
                circuit,
                cell: cell.into_inner().1,
            }))
        } else {
            Ok(None)
        }
    }
}

impl From<CreatedFast> for Cell {
    #[inline]
    fn from(cell: CreatedFast) -> Self {
        Self::from_fixed(
            CellHeader {
                command: CreatedFast::ID,
                circuit: cell.circuit.into(),
            },
            cell.into_inner(),
        )
    }
}

impl From<CreatedFast> for FixedCell {
    #[inline]
    fn from(v: CreatedFast) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for CreatedFast {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl CreatedFast {
    /// Cell ID of `CREATED_FAST`.
    pub const ID: u8 = 6;

    /// Creates new [`CreatedFast`].
    #[must_use]
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, y: [u8; 20], derived: [u8; 20]) -> Self {
        let p: &mut CreatedFastData = transmute_mut!(cell.data_mut());
        p.y = y;
        p.derived = derived;
        p.padding.fill(0);

        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    #[inline]
    fn get_ref(&self) -> &CreatedFastData {
        transmute_ref!(self.cell.data())
    }

    #[inline]
    fn get_mut(&mut self) -> &mut CreatedFastData {
        transmute_mut!(self.cell.data_mut())
    }

    /// Gets reference to payload.
    #[inline]
    #[must_use]
    pub fn y(&self) -> &[u8; 20] {
        &self.get_ref().y
    }

    /// Gets mutable reference to payload.
    #[inline]
    pub fn y_mut(&mut self) -> &mut [u8; 20] {
        &mut self.get_mut().y
    }

    /// Gets reference to derived key data.
    #[inline]
    #[must_use]
    pub fn derived(&self) -> &[u8; 20] {
        &self.get_ref().derived
    }

    /// Gets mutable reference to derived key data.
    #[inline]
    pub fn derived_mut(&mut self) -> &mut [u8; 20] {
        &mut self.get_mut().derived
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }
}
