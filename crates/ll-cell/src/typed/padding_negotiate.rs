//! `PADDING_NEGOTIATE` cell type.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::num::NonZeroU32;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};

use crate::cell::{AutoReturnFixed, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, ZeroCircID};
use crate::fixed::{FIXED_CELL_SIZE, FixedCell};

/// `PADDING_NEGOTIATE` version 0.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct PaddingNegotiateV0Data {
    command: u8,
    lo_ms: U16,
    hi_ms: U16,
}

macro_rules! paddingnegotiate {
    ($($l:ident<$t:ty> = $v:tt),+ $(,)?) => {
        #[allow(dead_code)]
        #[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
        #[repr(u8)]
        enum PaddingNegotiateCellData {
            $($l($t, [u8; const { FIXED_CELL_SIZE - size_of::<$t>() - 1 }]) = $v,)+
        }

        #[allow(dead_code)]
        impl PaddingNegotiateCellData {
            #[inline(always)]
            const fn rest(&self) -> &[u8] {
                match self {
                    $(Self::$l(_, s) => s,)*
                }
            }

            #[inline(always)]
            const fn rest_mut(&mut self) -> &mut [u8] {
                match self {
                    $(Self::$l(_, s) => s,)*
                }
            }
        }
    };
}

paddingnegotiate! {
    V0<PaddingNegotiateV0Data> = 0, V1<()> = 1, V2<()> = 2, V3<()> = 3, V4<()> = 4, V5<()> = 5, V6<()> = 6, V7<()> = 7,
    V8<()> = 8, V9<()> = 9, V10<()> = 10, V11<()> = 11, V12<()> = 12, V13<()> = 13, V14<()> = 14, V15<()> = 15,
    V16<()> = 16, V17<()> = 17, V18<()> = 18, V19<()> = 19, V20<()> = 20, V21<()> = 21, V22<()> = 22, V23<()> = 23,
    V24<()> = 24, V25<()> = 25, V26<()> = 26, V27<()> = 27, V28<()> = 28, V29<()> = 29, V30<()> = 30, V31<()> = 31,
    V32<()> = 32, V33<()> = 33, V34<()> = 34, V35<()> = 35, V36<()> = 36, V37<()> = 37, V38<()> = 38, V39<()> = 39,
    V40<()> = 40, V41<()> = 41, V42<()> = 42, V43<()> = 43, V44<()> = 44, V45<()> = 45, V46<()> = 46, V47<()> = 47,
    V48<()> = 48, V49<()> = 49, V50<()> = 50, V51<()> = 51, V52<()> = 52, V53<()> = 53, V54<()> = 54, V55<()> = 55,
    V56<()> = 56, V57<()> = 57, V58<()> = 58, V59<()> = 59, V60<()> = 60, V61<()> = 61, V62<()> = 62, V63<()> = 63,
    V64<()> = 64, V65<()> = 65, V66<()> = 66, V67<()> = 67, V68<()> = 68, V69<()> = 69, V70<()> = 70, V71<()> = 71,
    V72<()> = 72, V73<()> = 73, V74<()> = 74, V75<()> = 75, V76<()> = 76, V77<()> = 77, V78<()> = 78, V79<()> = 79,
    V80<()> = 80, V81<()> = 81, V82<()> = 82, V83<()> = 83, V84<()> = 84, V85<()> = 85, V86<()> = 86, V87<()> = 87,
    V88<()> = 88, V89<()> = 89, V90<()> = 90, V91<()> = 91, V92<()> = 92, V93<()> = 93, V94<()> = 94, V95<()> = 95,
    V96<()> = 96, V97<()> = 97, V98<()> = 98, V99<()> = 99, V100<()> = 100, V101<()> = 101, V102<()> = 102, V103<()> = 103,
    V104<()> = 104, V105<()> = 105, V106<()> = 106, V107<()> = 107, V108<()> = 108, V109<()> = 109, V110<()> = 110, V111<()> = 111,
    V112<()> = 112, V113<()> = 113, V114<()> = 114, V115<()> = 115, V116<()> = 116, V117<()> = 117, V118<()> = 118, V119<()> = 119,
    V120<()> = 120, V121<()> = 121, V122<()> = 122, V123<()> = 123, V124<()> = 124, V125<()> = 125, V126<()> = 126, V127<()> = 127,
    V128<()> = 128, V129<()> = 129, V130<()> = 130, V131<()> = 131, V132<()> = 132, V133<()> = 133, V134<()> = 134, V135<()> = 135,
    V136<()> = 136, V137<()> = 137, V138<()> = 138, V139<()> = 139, V140<()> = 140, V141<()> = 141, V142<()> = 142, V143<()> = 143,
    V144<()> = 144, V145<()> = 145, V146<()> = 146, V147<()> = 147, V148<()> = 148, V149<()> = 149, V150<()> = 150, V151<()> = 151,
    V152<()> = 152, V153<()> = 153, V154<()> = 154, V155<()> = 155, V156<()> = 156, V157<()> = 157, V158<()> = 158, V159<()> = 159,
    V160<()> = 160, V161<()> = 161, V162<()> = 162, V163<()> = 163, V164<()> = 164, V165<()> = 165, V166<()> = 166, V167<()> = 167,
    V168<()> = 168, V169<()> = 169, V170<()> = 170, V171<()> = 171, V172<()> = 172, V173<()> = 173, V174<()> = 174, V175<()> = 175,
    V176<()> = 176, V177<()> = 177, V178<()> = 178, V179<()> = 179, V180<()> = 180, V181<()> = 181, V182<()> = 182, V183<()> = 183,
    V184<()> = 184, V185<()> = 185, V186<()> = 186, V187<()> = 187, V188<()> = 188, V189<()> = 189, V190<()> = 190, V191<()> = 191,
    V192<()> = 192, V193<()> = 193, V194<()> = 194, V195<()> = 195, V196<()> = 196, V197<()> = 197, V198<()> = 198, V199<()> = 199,
    V200<()> = 200, V201<()> = 201, V202<()> = 202, V203<()> = 203, V204<()> = 204, V205<()> = 205, V206<()> = 206, V207<()> = 207,
    V208<()> = 208, V209<()> = 209, V210<()> = 210, V211<()> = 211, V212<()> = 212, V213<()> = 213, V214<()> = 214, V215<()> = 215,
    V216<()> = 216, V217<()> = 217, V218<()> = 218, V219<()> = 219, V220<()> = 220, V221<()> = 221, V222<()> = 222, V223<()> = 223,
    V224<()> = 224, V225<()> = 225, V226<()> = 226, V227<()> = 227, V228<()> = 228, V229<()> = 229, V230<()> = 230, V231<()> = 231,
    V232<()> = 232, V233<()> = 233, V234<()> = 234, V235<()> = 235, V236<()> = 236, V237<()> = 237, V238<()> = 238, V239<()> = 239,
    V240<()> = 240, V241<()> = 241, V242<()> = 242, V243<()> = 243, V244<()> = 244, V245<()> = 245, V246<()> = 246, V247<()> = 247,
    V248<()> = 248, V249<()> = 249, V250<()> = 250, V251<()> = 251, V252<()> = 252, V253<()> = 253, V254<()> = 254, V255<()> = 255,
}

/// `PADDING_NEGOTIATE` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/flow-control.html#link-padding).
pub struct PaddingNegotiate {
    /// Circuit ID.
    pub circuit: NonZeroU32,
    cell: FixedCell,
}

impl Debug for PaddingNegotiate {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("PaddingNegotiate").finish_non_exhaustive()
    }
}

impl TryFromCell for PaddingNegotiate {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnFixed::new(cell)?
            && cell.header().command == Self::ID
        {
            let circuit = NonZeroU32::new(cell.header().circuit).ok_or(ZeroCircID)?;
            if Self::validate_cell(cell.data().data()) {
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

impl From<PaddingNegotiate> for Cell {
    fn from(cell: PaddingNegotiate) -> Self {
        Self::from_fixed(
            CellHeader {
                command: PaddingNegotiate::ID,
                circuit: cell.circuit.get(),
            },
            cell.into_inner(),
        )
    }
}

impl From<PaddingNegotiate> for FixedCell {
    #[inline]
    fn from(v: PaddingNegotiate) -> FixedCell {
        v.into_inner()
    }
}

impl AsRef<FixedCell> for PaddingNegotiate {
    #[inline]
    fn as_ref(&self) -> &FixedCell {
        self.inner()
    }
}

impl PaddingNegotiate {
    /// Cell ID of `PADDING_NEGOTIATE`.
    pub const ID: u8 = 12;

    /// Creates new [`PaddingNegotiate`].
    #[must_use]
    pub fn new(circuit: NonZeroU32, mut cell: FixedCell, command: PaddingNegotiateData) -> Self {
        let p: &mut PaddingNegotiateCellData = transmute_mut!(cell.data_mut());
        *p = match command {
            PaddingNegotiateData::V0(command) => PaddingNegotiateCellData::V0(
                match command {
                    PaddingNegotiateV0::Stop => PaddingNegotiateV0Data {
                        command: 1,
                        lo_ms: U16::new(0),
                        hi_ms: U16::new(0),
                    },
                    PaddingNegotiateV0::Start { low, high } => PaddingNegotiateV0Data {
                        command: 2,
                        lo_ms: U16::new(low),
                        hi_ms: U16::new(high),
                    },
                },
                [0; _],
            ),
        };

        debug_assert!(
            Self::validate_cell(cell.data()),
            "cell format should be valid"
        );
        Self { circuit, cell }
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &FixedCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> FixedCell {
        self.cell
    }

    fn get_ref(&self) -> &PaddingNegotiateCellData {
        transmute_ref!(self.cell.data())
    }

    /// Gets padding negotiate data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> PaddingNegotiateData {
        match self.get_ref() {
            PaddingNegotiateCellData::V0(v, _) => PaddingNegotiateData::V0(match v.command {
                1 => PaddingNegotiateV0::Stop,
                2 => PaddingNegotiateV0::Start {
                    low: v.lo_ms.get(),
                    high: v.hi_ms.get(),
                },
                _ => unreachable!("unknown command"),
            }),
            _ => unreachable!("unknown version"),
        }
    }

    fn validate_cell(s: &[u8; FIXED_CELL_SIZE]) -> bool {
        matches!(
            transmute_ref!(s),
            PaddingNegotiateCellData::V0(PaddingNegotiateV0Data { command: 1 | 2, .. }, _)
        )
    }
}

/// Padding negotiation command version 0.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PaddingNegotiateV0 {
    /// Stop padding.
    Stop,
    /// Start padding.
    Start { low: u16, high: u16 },
}

/// Padding negotiation command.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PaddingNegotiateData {
    V0(PaddingNegotiateV0),
}
