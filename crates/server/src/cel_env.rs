//! What every kind of CEL the server works out shares: alert conditions, config and
//! template rules' conditions over facts, and the metrics templates work out.

use std::sync::{Arc, LazyLock};

use cel::common::ast::{CallExpr, EntryExpr, Expr, IdedExpr, operators};
use cel::extractors::Arguments;
use cel::{Env, ExecutionError, Value as CelValue};

/// CEL's own functions and macros, made once, as making them takes far longer than
/// working anything out.
pub static FUNCTIONS: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(Env::stdlib()));

/// What a sum is worked out with in place of CEL's own `+`, `-`, `*` and `/`, which
/// only work on two numbers of the same kind. Nobody can type them, as they aren't
/// names.
const SUMS: [(&str, &str); 4] = [
    (operators::ADD, "sum:+"),
    (operators::SUBSTRACT, "sum:-"),
    (operators::MULTIPLY, "sum:*"),
    (operators::DIVIDE, "sum:/"),
];

/// Adds the functions sums are worked out with to `context`.
pub fn add_sums(context: &mut cel::Context<'_, '_>) {
    // The names aren't CEL's own, so adding them can't fail.
    let _ = context.add_function("sum:+", |Arguments(args): Arguments| {
        sum(operators::ADD, &args)
    });
    let _ = context.add_function("sum:-", |Arguments(args): Arguments| {
        sum(operators::SUBSTRACT, &args)
    });
    let _ = context.add_function("sum:*", |Arguments(args): Arguments| {
        sum(operators::MULTIPLY, &args)
    });
    let _ = context.add_function("sum:/", |Arguments(args): Arguments| {
        sum(operators::DIVIDE, &args)
    });
}

/// A sum as it reads: a whole number and a fraction mix, and a division is never
/// cut to a whole number, so `cpu.usage / 2` and `commits / 60` are what they say,
/// while two whole numbers added, taken away or multiplied stay whole, so one can
/// pick from a list, as `tags[size(tags) - 1]` does, unless that's too big for a
/// whole number or below zero for one that can't be, when it's worked out as
/// fractions. Anything else is as CEL has it.
fn sum(operator: &str, args: &[CelValue]) -> Result<CelValue, ExecutionError> {
    match sum_as_given(operator, args) {
        Err(ExecutionError::Overflow(..)) => {
            let fractions: Vec<CelValue> = args
                .iter()
                .map(|value| match value {
                    CelValue::Int(whole) => CelValue::Float(*whole as f64),
                    CelValue::UInt(whole) => CelValue::Float(*whole as f64),
                    other => other.clone(),
                })
                .collect();
            sum_as_given(operator, &fractions)
        }
        worked_out => worked_out,
    }
}

fn sum_as_given(operator: &str, args: &[CelValue]) -> Result<CelValue, ExecutionError> {
    let [left, right] = args else {
        return Err(ExecutionError::invalid_argument_count(2, args.len()));
    };
    let as_fraction = |value: &CelValue| match value {
        CelValue::Int(whole) => Some(*whole as f64),
        CelValue::UInt(whole) => Some(*whole as f64),
        CelValue::Float(fraction) => Some(*fraction),
        _ => None,
    };
    let whole = matches!(
        (left, right),
        (CelValue::Int(_), CelValue::Int(_)) | (CelValue::UInt(_), CelValue::UInt(_))
    );
    let (left, right) = match (as_fraction(left), as_fraction(right)) {
        (Some(l), Some(r)) if operator == operators::DIVIDE || !whole => {
            (CelValue::Float(l), CelValue::Float(r))
        }
        _ => (left.clone(), right.clone()),
    };
    match operator {
        operators::ADD => left + right,
        operators::SUBSTRACT => left - right,
        operators::MULTIPLY => left * right,
        _ => left / right,
    }
}

/// Makes a sum worked out as [`sum`] has it, so `cpu.usage / 2` works as it reads.
/// Comparisons mix numbers already.
pub fn fraction_sum(call: &mut CallExpr) {
    if call.target.is_some() {
        return;
    }
    if let Some((_, ours)) = SUMS.iter().find(|(theirs, _)| *theirs == call.func_name) {
        call.func_name = (*ours).to_string();
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
        add_sums(&mut context);
        context.add_variable_from_value("x", CelValue::Float(1.5));
        context.add_variable_from_value(
            "tags",
            CelValue::List(std::sync::Arc::new(vec!["a".into(), "b".into()])),
        );
        context.resolve(&expr).unwrap()
    }

    #[test]
    fn whole_numbers_and_fractions_mix_in_sums_anywhere() {
        assert_eq!(worked_out("x * 2"), CelValue::Float(3.0));
        assert_eq!(worked_out("7 / 2"), CelValue::Float(3.5));
        assert_eq!(worked_out("[x + 1][0]"), CelValue::Float(2.5));
        assert_eq!(worked_out("[1, 2].map(n, n * x)[1]"), CelValue::Float(3.0));
    }

    #[test]
    fn whole_numbers_stay_whole_except_when_divided() {
        assert_eq!(
            worked_out("tags[size(tags) - 1]"),
            CelValue::String("b".to_string().into())
        );
        assert_eq!(
            worked_out("string(1 + 1)"),
            CelValue::String("2".to_string().into())
        );
        assert_eq!(worked_out("3 * 4"), CelValue::Int(12));
        // Too big for a whole number, or below zero for one that can't be.
        assert_eq!(
            worked_out("64000000000 * 1000000000"),
            CelValue::Float(6.4e19)
        );
        assert_eq!(worked_out("1u - 2u"), CelValue::Float(-1.0));
        assert_eq!(worked_out("120 / 60"), CelValue::Float(2.0));
        assert_eq!(
            worked_out("'a' + 'b'"),
            CelValue::String("ab".to_string().into())
        );
        assert_eq!(
            worked_out("duration('1m') + duration('1s') == duration('61s')"),
            CelValue::Bool(true)
        );
    }
}
