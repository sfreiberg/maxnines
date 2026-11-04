use std::collections::BTreeMap;

use anyhow::Result;
use serde_json::{Value, json};
use sysinfo::{CpuRefreshKind, System};

/// Gathers what this machine is, as opposed to what it's doing. Everything here
/// should rarely change, because each change is kept as history. That's why
/// swap size, which some systems resize on demand, isn't included.
pub fn gather(custom: &BTreeMap<String, Value>) -> Result<Value> {
    let mut system = System::new()?;
    system.refresh_memory();
    system.refresh_cpu_list(CpuRefreshKind::nothing());

    Ok(json!({
        "os": {
            "family": std::env::consts::OS,
            "name": System::name().ok(),
            "version": System::os_version().ok(),
            "long_version": System::long_os_version().ok(),
            "kernel": System::kernel_version().ok(),
        },
        "host": {
            "name": System::host_name().ok(),
            "arch": System::cpu_arch(),
        },
        "cpu": {
            "model": system.cpus().first().map(|cpu| cpu.brand().trim().to_string()),
            "physical_cores": System::physical_core_count().ok(),
            "logical_cores": system.cpus().len(),
        },
        "memory": {
            "total_bytes": system.total_memory(),
        },
        "custom": custom,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_built_in_facts() {
        let facts = gather(&BTreeMap::new()).unwrap();

        assert_eq!(facts["os"]["family"], std::env::consts::OS);
        assert!(facts["host"]["arch"].is_string());
        assert!(facts["cpu"]["logical_cores"].as_u64().unwrap() > 0);
        assert!(facts["memory"]["total_bytes"].as_u64().unwrap() > 0);
    }

    #[test]
    fn reports_custom_facts() {
        let custom = BTreeMap::from([("role".to_string(), json!("web"))]);

        assert_eq!(gather(&custom).unwrap()["custom"]["role"], "web");
    }

    #[test]
    fn gathering_twice_gives_the_same_facts() {
        // A difference here would fill the history with false changes.
        let custom = BTreeMap::new();
        assert_eq!(gather(&custom).unwrap(), gather(&custom).unwrap());
    }
}
