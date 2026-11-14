//! `env()` for config files, so that the agent's and the server's work the same.

use hcl::Value;
use hcl::eval::{Context, FuncArgs, FuncDef, ParamType};

/// `env("NAME")` in a config file, or `env("NAME", "default")`. An unset variable
/// with no default is an error, so that a typo can't quietly leave something empty.
fn env(args: FuncArgs) -> Result<Value, String> {
    let name = args
        .positional_args()
        .next()
        .and_then(Value::as_str)
        .unwrap_or_default();
    match (std::env::var(name), args.variadic_args().next()) {
        (Ok(value), _) => Ok(Value::from(value)),
        (Err(_), Some(default)) => Ok(default.clone()),
        (Err(_), None) => Err(format!("environment variable {name} isn't set")),
    }
}

/// What expressions in a config file can use.
pub fn config_context() -> Context<'static> {
    let mut context = Context::new();
    context.declare_func(
        "env",
        FuncDef::builder()
            .param(ParamType::String)
            .variadic_param(ParamType::String)
            .build(env),
    );
    context
}
