use evm::{executor::stack::{PrecompileFailure, PrecompileOutput}, Context, ExitSucceed, ExitError};

pub type PrecompileResult = Result<PrecompileOutput, PrecompileFailure>;

/// One single precompile used by EVM engine.
pub trait Precompile {
    /// Try to execute the precompile. Calculate the amount of gas needed with given `input` and
    /// `target_gas`. Return `Ok(status, output, gas_used)` if the execution is
    /// successful. Otherwise return `Err(_)`.
    fn execute(
        input: &[u8],
        target_gas: Option<u64>,
        context: &Context,
        is_static: bool,
        ) -> PrecompileResult;
}

pub trait LinearCostPrecompile {
    const BASE: u64;
    const WORD: u64;

    fn execute(
        input: &[u8],
        cost: u64,
        ) -> core::result::Result<(ExitSucceed, Vec<u8>), PrecompileFailure>;
}

impl<T: LinearCostPrecompile> Precompile for T {
    fn execute(input: &[u8], target_gas: Option<u64>, _: &Context, _: bool) -> PrecompileResult {
        let cost = ensure_linear_cost(target_gas, input.len() as u64, T::BASE, T::WORD)?;

        let (exit_status, output) = T::execute(input, cost)?;
        Ok(PrecompileOutput {
            exit_status,
            cost,
            output,
            logs: Default::default(),
        })
    }
}

fn ensure_linear_cost(
    target_gas: Option<u64>,
    len: u64,
    base: u64,
    word: u64,
    ) -> Result<u64, PrecompileFailure> {
    let cost = base
        .checked_add(word.checked_mul(len.saturating_add(31) / 32).ok_or(
                PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                },
                )?)
        .ok_or(PrecompileFailure::Error {
            exit_status: ExitError::OutOfGas,
        })?;

    if let Some(target_gas) = target_gas {
        if cost > target_gas {
            return Err(PrecompileFailure::Error {
                exit_status: ExitError::OutOfGas,
            });
        }
    }

    Ok(cost)
}

