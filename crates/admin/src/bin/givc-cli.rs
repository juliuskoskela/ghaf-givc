// SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use givc::endpoint::{EndpointConfig, TlsConfig};
use givc::types::{TransportConfig, UnitType};
use givc::utils::vsock::parse_vsock_addr;
use givc_client::client::AdminClient;
use givc_common::address::EndpointAddress;
use givc_common::pb;
use lazy_regex::regex;
use ota_update::cli::{CachixOptions, QueryUpdates, query_updates};
use serde::ser::Serialize;
use std::path::PathBuf;
use std::time;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, interval, sleep, timeout};
use tonic::Code;
use tracing::info;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "givc-cli")]
#[command(about = "A givc CLI application", long_about = None)]
struct Cli {
    #[arg(long, env = "GIVC_ADDR", default_missing_value = "127.0.0.1")]
    addr: String,
    #[arg(long, env = "GIVC_PORT", default_missing_value = "9000", value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    #[arg(long, env = "GIVC_NAME", default_missing_value = "admin.ghaf")]
    name: String, // for TLS service name

    #[arg(long)]
    vsock: Option<String>,

    #[arg(long, env = "GIVC_CA_CERT")]
    cacert: Option<PathBuf>,

    #[arg(long, env = "GIVC_HOST_CERT")]
    cert: Option<PathBuf>,

    #[arg(long, env = "GIVC_HOST_KEY")]
    key: Option<PathBuf>,

    #[arg(long, env = "GIVC_NO_TLS", default_value_t = false)]
    notls: bool,

    /// Delivery timeout in seconds for `--direct` lifecycle calls. Bounds *delivery* to the
    /// agent, not the guest poweroff itself; keep it well below the host's microvm
    /// `TimeoutStopSec` so a fallback still has budget. Defaults to 3s. Marked `global` so it
    /// may be given after the subcommand (e.g. `start service ... poweroff.target --timeout 8`).
    #[arg(long, env = "GIVC_TIMEOUT", global = true)]
    timeout: Option<u64>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum StartSub {
    App {
        app: String,
        #[arg(long)]
        vm: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Vm {
        vm: String,
    },
    Service {
        servicename: String,
        #[arg(long)]
        vm: String,
        /// Deliver the unit start directly to the target VM's agent, bypassing the admin
        /// coordinator. `--addr`/`--port`/`--vsock` and `--name` are then interpreted as the
        /// *guest agent* endpoint (not the admin), and `--vm` becomes a cosmetic label.
        /// Returns the documented lifecycle exit codes (see `direct_lifecycle`).
        #[arg(long, default_value_t = false)]
        direct: bool,
    },
}

impl StartSub {
    async fn start(self, admin: AdminClient) -> anyhow::Result<()> {
        let response = match self {
            StartSub::App { app, vm, args } => admin.start_app(app, vm, args).await?,
            StartSub::Vm { vm } => admin.start_vm(vm).await?,
            // `--direct` is intercepted in `main` before the admin client is built; reaching
            // here means a normal admin-routed service start.
            StartSub::Service {
                servicename,
                vm,
                direct: _,
            } => admin.start_service(servicename, vm).await?,
        };
        println!("{response:?}");
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum UpdateSub {
    Query(QueryUpdates),
    List,
    Cachix(CachixOptions),
}

#[derive(Debug, Parser)]
struct Notification {
    vm: String,
    #[arg(long, default_value = "Default Event")]
    event: String,
    #[arg(long, default_value = "Default Title")]
    title: String,
    #[arg(long, default_value = "Normal")]
    urgency: String,
    #[arg(long, default_value = "dialog-information")]
    icon: String,
    #[arg(long, default_value = "(no message)")]
    message: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Start {
        #[command(subcommand)]
        start: StartSub,
    },
    Stop {
        app: String,
    },
    Pause {
        app: String,
    },
    Resume {
        app: String,
    },
    Reboot {},
    Poweroff {},
    Suspend {},
    Wakeup {},
    Sysinfo {},
    Query {
        #[arg(long, default_value_t = false)]
        as_json: bool, // Would it useful for scripts?
        #[arg(long)]
        by_type: Option<u32>, // FIXME:  parse UnitType by names?
        #[arg(long)]
        by_name: Vec<String>, // list of names, all if empty?
    },
    QueryList {
        // Even if I believe that QueryList is temporary
        #[arg(long, default_value_t = false)]
        as_json: bool,
    },
    GetStatus {
        vm_name: String,
        unit_name: String,
    },

    SetLocale {
        locales: Vec<String>,
    },
    SetTimezone {
        timezone: String,
    },
    GetStats {
        vm_name: String,
    },
    Watch {
        #[arg(long, default_value_t = false)]
        as_json: bool,
        #[arg(long, default_value_t = false)]
        initial: bool,
        #[arg(long)]
        limit: Option<u32>,
    },
    NotifyUser {
        #[command(flatten)]
        notification: Notification,
    },
    Update {
        #[command(subcommand)]
        update: UpdateSub,
    },
    Test {
        #[command(subcommand)]
        test: Test,
    },
    Ctap {
        op: String,
    },
}

fn unit_type_parse(s: &str) -> anyhow::Result<UnitType> {
    s.parse::<u32>()?.try_into()
}

fn optional_bool_to_display(state: Option<bool>) -> &'static str {
    match state {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn parse_locales(locale_assigns: Vec<String>) -> anyhow::Result<Vec<pb::locale::LocaleAssignment>> {
    let validator =
        regex!(r"^(?:C|POSIX|[a-z]{2}(?:_[A-Z]{2})?(?:@[a-zA-Z0-9]+)?)(?:\.[-a-zA-Z0-9]+)?$");

    let Some(first) = locale_assigns.first() else {
        anyhow::bail!("No locale assignments provided");
    };

    if validator.is_match(first) {
        return Ok(vec![pb::locale::LocaleAssignment {
            key: pb::locale::LocaleMacroKey::Lang as i32,
            // Item existence validated earlier, `.unwrap()` is safe
            value: locale_assigns.into_iter().next().unwrap(),
        }]);
    }

    let mut parsed_assigns = Vec::new();
    let mut has_lang = false;

    for assign in &locale_assigns {
        let Some((key, value)) = assign.split_once('=') else {
            anyhow::bail!("Invalid locale assignment format: '{assign}'");
        };
        let Some(key_enum) = pb::locale::LocaleMacroKey::from_str_name(key) else {
            anyhow::bail!("Unknown locale key: '{key}'");
        };

        // Validate value for each key
        if !validator.is_match(value) {
            anyhow::bail!("Invalid locale value in '{assign}'");
        }

        if key_enum == pb::locale::LocaleMacroKey::LcAll {
            // LC_ALL overrides all other locale settings, so we can ignore other keys
            return Ok(vec![pb::locale::LocaleAssignment {
                key: pb::locale::LocaleMacroKey::LcAll as i32,
                value: value.to_string(),
            }]);
        }
        if key_enum == pb::locale::LocaleMacroKey::Lang {
            has_lang = true;
        }
        parsed_assigns.push(pb::locale::LocaleAssignment {
            key: key_enum.into(),
            value: value.to_string(),
        });
    }

    if !has_lang {
        anyhow::bail!("At least one of LANG or LC_ALL assignment is required");
    }

    Ok(parsed_assigns)
}

#[derive(Debug, Subcommand)]
enum Test {
    Ensure {
        #[arg(long, default_missing_value = "1")]
        retry: i32,
        service: String,
        #[arg(long, value_parser=unit_type_parse)]
        r#type: Option<UnitType>,
        #[arg(long)]
        vm: Option<String>,
    },
}

impl Test {
    async fn handle(self, admin: AdminClient) -> anyhow::Result<()> {
        let Test::Ensure {
            service,
            retry,
            r#type,
            vm,
        } = self;

        let mut ival = interval(time::Duration::from_secs(1));
        for _ in 0..retry {
            ival.tick().await;
            if let Some(r) = admin
                .query_list()
                .await?
                .into_iter()
                .find(|r| r.name == service)
            {
                if r#type.is_some_and(|t| t.vm != r.vm_type || t.service != r.service_type) {
                    anyhow::bail!("test failed '{service}' registered but of wrong type");
                } else if vm.is_some() && vm != r.vm_name {
                    anyhow::bail!("test failed '{service}' registered but on wrong VM");
                }
                return Ok(());
            }
        }
        anyhow::bail!("test failed '{service}' not registered");
    }
}

impl UpdateSub {
    async fn handle(self, admin: AdminClient) -> anyhow::Result<()> {
        match self {
            UpdateSub::Query(query) => query_updates(query).await?,
            UpdateSub::List => {
                let response = admin.list_generations().await?;
                println!("{response:?}");
            }
            UpdateSub::Cachix(CachixOptions {
                pin_name,
                cachix_host,
                cache,
                token,
            }) => {
                admin
                    .set_generation_cachix(pin_name, cachix_host, cache, token)
                    .await?;
            }
        }
        Ok(())
    }
}

async fn ctap(admin: AdminClient, operation: String) -> anyhow::Result<()> {
    let mut payload = vec![];
    tokio::io::stdin().read_to_end(&mut payload).await?;
    let (op, args) = if let Some((op, args)) = operation.split_once('+') {
        (op.to_string(), vec![args.to_string()])
    } else {
        (operation, vec![])
    };
    let output = admin.ctap(op, args, payload).await?;
    tokio::io::stdout().write_all(&output).await?;
    Ok(())
}

async fn notify_user(admin: AdminClient, notification: Notification) -> anyhow::Result<()> {
    let Notification {
        vm,
        event,
        title,
        urgency,
        icon,
        message,
    } = notification;
    let reply = admin
        .notify_user(vm, event, title, urgency, icon, message)
        .await?;
    print!("{reply:?}");
    Ok(())
}

async fn sysinfo(admin: AdminClient) -> anyhow::Result<()> {
    let status = admin.sysinfo().await?;
    println!("Ghaf Version: {}", status.ghaf_version);
    println!(
        "Secure Boot: {}",
        optional_bool_to_display(status.secure_boot)
    );
    println!(
        "Disk Encryption: {}",
        optional_bool_to_display(status.disk_encrypted)
    );
    Ok(())
}

// Process exit codes for the coordinator-independent lifecycle path
// (`start service --vm <vm> <unit> --direct`). This is a stable contract consumed by the
// host's microvm `ExecStop`:
//   0  ACCEPTED            delivered: a clean reply, OR the connection dropped / the deadline
//                          fired AFTER the request was sent (the normal poweroff case, where
//                          the agent is killed mid-shutdown before it can reply).
//   10 UNREACHABLE         connect() failed (refused / no route / TLS handshake) — nothing was
//                          delivered, so the host can fall back immediately.
//   11 TIMEOUT_PRE_ACCEPT  `--timeout` fired during connect, before the request was sent.
//   12 DENIED              PermissionDenied / Unauthenticated (e.g. caller IP not in cert SAN).
//   14 AGENT_ERROR         the agent returned an error Status (e.g. unit not whitelisted).
//   2  USAGE               argument parse error (emitted by clap directly).
const EXIT_ACCEPTED: i32 = 0;
const EXIT_UNREACHABLE: i32 = 10;
const EXIT_TIMEOUT_PRE_ACCEPT: i32 = 11;
const EXIT_DENIED: i32 = 12;
const EXIT_AGENT_ERROR: i32 = 14;

const DEFAULT_DIRECT_TIMEOUT_SECS: u64 = 3;

/// If `cmd` is a `--direct` `start service` invocation, return the target unit name.
fn direct_service_target(cmd: &Commands) -> Option<&str> {
    match cmd {
        Commands::Start {
            start:
                StartSub::Service {
                    servicename,
                    direct: true,
                    ..
                },
        } => Some(servicename),
        _ => None,
    }
}

/// Deliver a lifecycle unit start directly to a VM's agent `UnitControlService`, bypassing the
/// admin coordinator. Returns the process exit code (see the `EXIT_*` contract above).
///
/// The connection reuses the CLI's existing mTLS identity, and the guest agent's existing unit
/// whitelist authorizes the unit — so this preserves the same security guarantees as the
/// admin-mediated path while removing the dependency on the coordinator being alive.
async fn direct_lifecycle(
    address: EndpointAddress,
    tls: Option<(String, TlsConfig)>,
    unit: String,
    timeout_secs: u64,
) -> i32 {
    use givc_common::pb::systemd::UnitRequest;
    use givc_common::pb::systemd::unit_control_service_client::UnitControlServiceClient;

    let (tls_name, tls) = match tls {
        Some((name, tls)) => (name, Some(tls)),
        None => (String::from("bogus(no tls)"), None),
    };
    let endpoint = EndpointConfig {
        transport: TransportConfig { address, tls_name },
        tls,
    };

    let budget = Duration::from_secs(timeout_secs);
    let deadline = Instant::now() + budget;

    // Phase 1 — connect to the agent. A connect failure means nothing was delivered, so the
    // host can fall back immediately. One in-budget retry absorbs a transient blip during a
    // busy host shutdown (EndpointConfig's own connect timeout is a tight 300ms).
    let mut channel = None;
    for attempt in 0..2u32 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            info!("direct: connect budget exhausted before delivery");
            return EXIT_TIMEOUT_PRE_ACCEPT;
        }
        match timeout(remaining, endpoint.connect()).await {
            Ok(Ok(ch)) => {
                channel = Some(ch);
                break;
            }
            Ok(Err(e)) => {
                info!("direct: connect attempt {attempt} failed: {e:#}");
                // Brief backoff before the single retry, only if budget remains.
                let nap = Duration::from_millis(100);
                if attempt == 0 && deadline.saturating_duration_since(Instant::now()) > nap {
                    sleep(nap).await;
                }
            }
            Err(_elapsed) => {
                info!("direct: connect timed out before delivery");
                return EXIT_TIMEOUT_PRE_ACCEPT;
            }
        }
    }
    let Some(channel) = channel else {
        return EXIT_UNREACHABLE;
    };

    // Phase 2 — issue StartUnit. Once the request is on the wire, a dropped connection or an
    // elapsed deadline means the agent accepted it and is tearing the VM down: that is SUCCESS,
    // not a transport error. We inspect the raw `tonic::Status` here (deliberately NOT
    // `rewrap_err`, which discards the gRPC `Code`) and translate to the documented exit codes.
    let mut client = UnitControlServiceClient::new(channel);
    let request = UnitRequest { unit_name: unit };
    let remaining = deadline.saturating_duration_since(Instant::now());
    match timeout(remaining, client.start_unit(request)).await {
        // Deadline after the request was sent: assume accepted (agent is shutting down).
        Err(_elapsed) => EXIT_ACCEPTED,
        // Clean reply (e.g. the agent acked the lifecycle target).
        Ok(Ok(_response)) => EXIT_ACCEPTED,
        Ok(Err(status)) => match status.code() {
            // Connection reset / cancelled / deadline once the request was already sent.
            Code::Unavailable | Code::Cancelled | Code::Aborted | Code::DeadlineExceeded => {
                EXIT_ACCEPTED
            }
            Code::PermissionDenied | Code::Unauthenticated => EXIT_DENIED,
            // Unknown (server-side failure, e.g. unit not whitelisted) and anything else.
            _ => EXIT_AGENT_ERROR,
        },
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    givc::trace_init()?;

    let cli = Cli::parse();
    info!("CLI is {:#?}", cli);

    let tls = if cli.notls {
        None
    } else {
        Some((
            cli.name.clone(),
            TlsConfig {
                ca_cert_file_path: cli.cacert.expect("cacert is required"),
                cert_file_path: cli.cert.expect("cert is required"),
                key_file_path: cli.key.expect("key is required"),
                tls_name: Some(cli.name),
            },
        ))
    };

    // R1: coordinator-independent lifecycle delivery. When `--direct` is set on
    // `start service`, dial the guest agent's UnitControlService directly — bypassing the admin
    // coordinator, which during a full-system shutdown may itself be tearing down — and exit
    // with the documented lifecycle status code. This is intercepted before the AdminClient is
    // built so no connection to the admin is attempted.
    if let Some(unit) = direct_service_target(&cli.command) {
        let address = match &cli.vsock {
            Some(vsock) => EndpointAddress::Vsock(parse_vsock_addr(vsock)?),
            None => EndpointAddress::Tcp {
                addr: cli.addr.clone(),
                port: cli.port,
            },
        };
        let code = direct_lifecycle(
            address,
            tls,
            unit.to_string(),
            cli.timeout.unwrap_or(DEFAULT_DIRECT_TIMEOUT_SECS),
        )
        .await;
        std::process::exit(code);
    }

    // FIXME; big kludge, but allow to test vsock connection
    let admin = if let Some(vsock) = cli.vsock {
        info!("Connection diverted to VSock");
        AdminClient::from_endpoint_address(EndpointAddress::Vsock(parse_vsock_addr(&vsock)?), tls)
    } else {
        AdminClient::new(cli.addr, cli.port, tls)
    };

    match cli.command {
        Commands::Test { test } => test.handle(admin).await?,
        Commands::Start { start } => start.start(admin).await?,
        Commands::Stop { app } => admin.stop(app).await?,
        Commands::Pause { app } => admin.pause(app).await?,
        Commands::Resume { app } => admin.resume(app).await?,
        Commands::Reboot {} => admin.reboot().await?,
        Commands::Poweroff {} => admin.poweroff().await?,
        Commands::Suspend {} => admin.suspend().await?,
        Commands::Wakeup {} => admin.wakeup().await?,
        Commands::Sysinfo {} => sysinfo(admin).await?,

        Commands::Query {
            by_type,
            by_name,
            as_json,
        } => {
            let ty = match by_type {
                Some(x) => Some(UnitType::try_from(x)?),
                _ => None,
            };
            let reply = admin.query(ty, by_name).await?;
            dump(reply, as_json)?;
        }
        Commands::QueryList { as_json } => {
            let reply = admin.query_list().await?;
            dump(reply, as_json)?;
        }

        Commands::GetStatus { vm_name, unit_name } => {
            let reply = admin.get_status(vm_name, unit_name).await?;
            print!("{reply:?}");
        }

        Commands::SetLocale { locales } => {
            admin.set_locales(parse_locales(locales)?).await?;
        }

        Commands::SetTimezone { timezone } => {
            admin.set_timezone(timezone).await?;
        }

        Commands::GetStats { vm_name } => {
            println!("{:?}", admin.get_stats(vm_name).await?);
        }

        Commands::Watch {
            as_json,
            limit,
            initial: dump_initial,
        } => {
            let watch = admin.watch().await?;
            let mut limit = limit.map(|l| 0..l);

            if dump_initial {
                dump(watch.initial, as_json)?;
            }

            while limit.as_mut().is_none_or(|l| l.next().is_some()) {
                dump(watch.channel.recv().await?, as_json)?;
            }
        }

        Commands::Ctap { op } => {
            ctap(admin, op).await?;
        }

        Commands::NotifyUser { notification } => {
            notify_user(admin, notification).await?;
        }

        Commands::Update { update } => update.handle(admin).await?,
    }

    Ok(())
}

fn dump<Q>(qr: Q, as_json: bool) -> anyhow::Result<()>
where
    Q: std::fmt::Debug + Serialize,
{
    if as_json {
        let js = serde_json::to_string(&qr)?;
        println!("{js}");
    } else {
        println!("{qr:#?}");
    }
    Ok(())
}
