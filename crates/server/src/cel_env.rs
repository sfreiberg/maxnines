//! What every kind of CEL the server works out shares: alert conditions, config and
//! template rules' conditions over facts, and the metrics templates work out.

use std::sync::{Arc, LazyLock};

use cel::common::ast::{CallExpr, EntryExpr, Expr, IdedExpr, operators};
use cel::extractors::Arguments;
use cel::{Env, ExecutionError, Value as CelValue};

/// CEL's own functions and macros, made once, as making them takes far longer than
/// working anything out.
pub static FUNCTIONS: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(Env::stdlib()));

/// What every number a sum works on goes through, so whole numbers and fractions mix:
/// CEL only adds two numbers of the same kind. Nobody can type it, as it isn't a name.
pub const NUMBER: &str = "number:";

/// A whole number as one with a fraction, and anything else as it is.
pub fn number(Arguments(args): Arguments) -> Result<CelValue, ExecutionError> {
    match args.as_slice() {
        [CelValue::Int(whole)] => Ok(CelValue::Float(*whole as f64)),
        [CelValue::UInt(whole)] => Ok(CelValue::Float(*whole as f64)),
        [other] => Ok(other.clone()),
        _ => Err(ExecutionError::invalid_argument_count(1, args.len())),
    }
}

/// Makes a sum's whole numbers ones with fractions as it's worked out, so
/// `cpu.usage / 2` works as it reads. Comparisons mix them already.
pub fn fraction_sum(call: &mut CallExpr) {
    let sums = matches!(
        call.func_name.as_str(),
        operators::ADD | operators::SUBSTRACT | operators::MULTIPLY | operators::DIVIDE
    );
    if !sums || call.target.is_some() {
        return;
    }
    for arg in &mut call.args {
        let inner = std::mem::take(arg);
        *arg = IdedExpr {
            id: inner.id,
            expr: Expr::Call(CallExpr {
                func_name: NUMBER.to_string(),
                target: None,
                args: vec![inner],
            }),
        };
    }
}

/// [`fraction_sum`] for every sum anywhere in an expression.
pub fn fractions(expr: &mut IdedExpr) {
    match &mut expr.expr {
        Expr::Call(call) => {
            if let Some(target) = &mut call.target {
                fractions(target);
            }
            call.args.iter_mut().for_each(fractions);
            fraction_sum(call);
        }
        Expr::Select(select) => fractions(&mut select.operand),
        Expr::Comprehension(comprehension) => {
            for part in [
                &mut comprehension.iter_range,
                &mut comprehension.accu_init,
                &mut comprehension.loop_cond,
                &mut comprehension.loop_step,
                &mut comprehension.result,
            ] {
                fractions(part);
            }
        }
        Expr::List(list) => list.elements.iter_mut().for_each(fractions),
        Expr::Map(map) => map
            .entries
            .iter_mut()
            .for_each(|entry| entry_fractions(&mut entry.expr)),
        Expr::Struct(fields) => fields
            .entries
            .iter_mut()
            .for_each(|entry| entry_fractions(&mut entry.expr)),
        Expr::Unspecified | Expr::Ident(_) | Expr::Literal(_) => {}
    }
}

fn entry_fractions(entry: &mut EntryExpr) {
    match entry {
        EntryExpr::MapEntry(map) => {
            fractions(&mut map.key);
            fractions(&mut map.value);
        }
        EntryExpr::StructField(field) => fractions(&mut field.value),
    }
}

#[cfg(test)]
mod tests {
    use cel::{Context, Program};

    use super::*;

    fn worked_out(text: &str) -> CelValue {
        let mut expr = Program::compile(text).unwrap().expression().clone();
        fractions(&mut expr);
        let mut context = Context::with_env(FUNCTIONS.clone());
        context.add_function(NUMBER, number).unwrap();
        context.add_variable_from_value("x", CelValue::Float(1.5));
        context.resolve(&expr).unwrap()
    }

    #[test]
    fn whole_numbers_and_fractions_mix_in_sums_anywhere() {
        assert_eq!(worked_out("x * 2"), CelValue::Float(3.0));
        assert_eq!(worked_out("7 / 2"), CelValue::Float(3.5));
        assert_eq!(worked_out("[x + 1][0]"), CelValue::Float(2.5));
        assert_eq!(worked_out("[1, 2].map(n, n * x)[1]"), CelValue::Float(3.0));
    }
}
