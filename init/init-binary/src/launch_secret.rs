use std::env;
use std::fs::{self, File};
use std::io::Read;

use anyhow::{Context, bail, ensure};
use nix::mount::{self, MsFlags};

const SECRET_MOUNT: &str = "/run/krun-security";
const SECRET_PATH: &str = "/run/krun-security/secrets/coco/cmdline";
const MAX_SECRET_BYTES: u64 = 2048;

pub struct LaunchSecret {
    pub verity: String,
    pub process_args: Vec<String>,
}

pub fn read_and_apply() -> anyhow::Result<LaunchSecret> {
    let command_line = read_command_line_secret()?;
    let tokens = split_command_line(&command_line)?;
    let delimiter = tokens.iter().position(|token| token == "--");
    let (environment, process_args) = match delimiter {
        Some(index) => (&tokens[..index], tokens[index + 1..].to_vec()),
        None => (&tokens[..], Vec::new()),
    };

    let mut verity = None;
    let mut init_count = 0;
    let mut workdir_count = 0;
    for token in environment {
        if token == "tsi_hijack" {
            // SAFETY: PID 1 is single-threaded while importing its launch
            // configuration, before any workload or helper thread is started.
            unsafe { env::set_var("KRUN_TSI_HIJACK", "1") };
            continue;
        }
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if !valid_environment_name(name) {
            continue;
        }
        if name == "KRUN_TEE_VERITY" {
            ensure!(verity.is_none(), "duplicate KRUN_TEE_VERITY launch setting");
            verity = Some(value.to_string());
            continue;
        }
        if name == "KRUN_INIT" {
            init_count += 1;
            ensure!(init_count == 1, "duplicate KRUN_INIT launch setting");
        } else if name == "KRUN_WORKDIR" {
            workdir_count += 1;
            ensure!(workdir_count == 1, "duplicate KRUN_WORKDIR launch setting");
        }
        ensure!(
            name != "KRUN_TEE_AUTHENTICATED_ROOT",
            "KRUN_TEE_AUTHENTICATED_ROOT is reserved for measured init"
        );
        // SAFETY: PID 1 is single-threaded while importing its launch
        // configuration, before any workload or helper thread is started.
        unsafe { env::set_var(name, value) };
    }

    let verity = verity.context("confidential launch is missing KRUN_TEE_VERITY")?;

    Ok(LaunchSecret {
        verity,
        process_args,
    })
}

fn read_command_line_secret() -> anyhow::Result<String> {
    fs::create_dir_all(SECRET_MOUNT).context("create securityfs mountpoint")?;
    mount::mount(
        Some("securityfs"),
        SECRET_MOUNT,
        Some("securityfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .context("mount launch-secret securityfs")?;

    let result = (|| {
        let bytes = read_and_wipe_secret(SECRET_PATH)?;
        ensure!(
            bytes.len() <= MAX_SECRET_BYTES as usize,
            "confidential launch command line exceeds 2048 bytes"
        );
        String::from_utf8(bytes).context("launch command line is not UTF-8")
    })();

    let unmount_result = mount::umount(SECRET_MOUNT).context("unmount launch-secret securityfs");
    match (result, unmount_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(command_line), Ok(())) => Ok(command_line),
    }
}

fn read_and_wipe_secret(path: &str) -> anyhow::Result<Vec<u8>> {
    let read_result = (|| {
        let mut bytes = Vec::new();
        File::open(path)
            .context("open confidential launch command line")?
            .take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read confidential launch command line")?;
        Ok(bytes)
    })();
    let wipe_result = fs::remove_file(path).context("wipe confidential launch command line");

    match (read_result, wipe_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(bytes), Ok(())) => Ok(bytes),
    }
}

fn split_command_line(input: &str) -> anyhow::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;

    for character in input.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            started = true;
            continue;
        }
        if character == '\\' {
            escaped = true;
            started = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                token.push(character);
            }
            started = true;
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
            started = true;
        } else if character.is_whitespace() {
            if started {
                tokens.push(std::mem::take(&mut token));
                started = false;
            }
        } else {
            token.push(character);
            started = true;
        }
    }

    ensure!(!escaped, "launch command line ends with an escape");
    if quote.is_some() {
        bail!("launch command line contains an unterminated quote");
    }
    if started {
        tokens.push(token);
    }
    Ok(tokens)
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SECRET: AtomicU64 = AtomicU64::new(0);

    fn temporary_secret_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "krun-launch-secret-{}-{}",
            std::process::id(),
            NEXT_SECRET.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn parses_launch_environment_and_process_arguments() {
        let tokens = split_command_line(
            r#"console=hvc0 KRUN_INIT=/guest "TERM=dumb" EMPTY="" -- "/path with spaces" plain\ arg"#,
        )
        .unwrap();

        assert_eq!(
            tokens,
            [
                "console=hvc0",
                "KRUN_INIT=/guest",
                "TERM=dumb",
                "EMPTY=",
                "--",
                "/path with spaces",
                "plain arg",
            ]
        );
    }

    #[test]
    fn rejects_truncated_escaping_or_quoting() {
        assert!(split_command_line("KRUN_INIT=bad\\").is_err());
        assert!(split_command_line(r#"KRUN_INIT="bad"#).is_err());
    }

    #[test]
    fn validates_environment_names() {
        assert!(valid_environment_name("KRUN_TEE_VERITY"));
        assert!(valid_environment_name("lower_case"));
        assert!(!valid_environment_name("9INVALID"));
        assert!(!valid_environment_name("BAD-NAME"));
    }

    #[test]
    fn wipes_secret_before_validating_size() {
        let path = temporary_secret_path();
        fs::write(&path, vec![b'x'; MAX_SECRET_BYTES as usize + 1]).unwrap();

        let bytes = read_and_wipe_secret(path.to_str().unwrap()).unwrap();

        assert_eq!(bytes.len(), MAX_SECRET_BYTES as usize + 1);
        assert!(!path.exists());
    }
}
