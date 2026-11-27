// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#![doc = include_str!("../README.md")]
/// Tool to display and create C2PA security testing content
///
/// Example command: ./target/x86_64-apple-darwin/release/c2pa-attacks \
/// ./sample/C.jpg  -m ./sample/test.json -o ./sample_out/C_mod.jpg \
/// -f -t author -a ./attacks/xss.txt
use std::{
    fs::{create_dir_all, remove_file, File},
    io::{self, BufRead},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    assertions::{labels, Metadata},
    format_from_path,
    settings::{Settings, TrustAnchor},
    Builder, ClaimGeneratorInfo, Context as C2paContext, Error, Ingredient, ManifestAssertionKind,
    ManifestDefinition, Reader,
};
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Env;
use etcetera::BaseStrategy;
use log::debug;
use regex::{NoExpand, Regex};
use serde::Deserialize;
use serde_json::{json, Map, Value};

mod signer;
// This is not used in the current implementation
/* use serde::Deserialize; */
use std::fs;

use signer::SignConfig;
use url::Url;

/// Sidecar trust files stored next to the settings file (`--settings` parent directory).
const SIDECAR_TRUST_LIST_PEM: &str = "c2pa-trust-list.pem";
const SIDECAR_TRUST_LIST_LEGACY_PEM: &str = "c2pa-trust-list-legacy.pem";
const SIDECAR_TRUST_STORE_CFG: &str = "c2pa-trust-store.cfg";
const SIDECAR_TRUST_ALLOWED: &str = "c2pa-trust-allowed.sha256.txt";
const LEGACY_CREATIVE_WORK: &str = "stds.schema-org.CreativeWork";
const SCHEMA_NAMESPACE: &str = "https://schema.org/";
const ATTACK_REJECTED_EXIT_CODE: u8 = 3;

#[derive(Debug)]
struct AttackRejected(Error);

impl std::fmt::Display for AttackRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "attack rejected by SDK: {}", self.0)
    }
}

impl std::error::Error for AttackRejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn signing_error(error: Error, target: Target) -> anyhow::Error {
    let rejected = match (&error, target) {
        (Error::BadParam(message), Target::Label) => message == "invalid Claim GUID",
        (Error::ClaimEncoding, Target::Vendor) => true,
        (Error::InvalidManifest(validation), Target::Vendor) => {
            validation.active_manifest().is_some_and(|statuses| {
                !statuses.failure().is_empty()
                    && statuses.failure().iter().all(|status| {
                        status.code() == "claim.malformed"
                            && status.explanation() == Some("claim box label invalid")
                    })
            }) && validation.ingredient_deltas().is_none_or(|ingredients| {
                ingredients
                    .iter()
                    .all(|ingredient| ingredient.validation_deltas().failure().is_empty())
            })
        }
        _ => false,
    };
    if rejected {
        AttackRejected(error).into()
    } else {
        error.into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum Target {
    Author,
    Title,
    Format,
    Label,
    Vendor,
    PersonIdentifier,
    InstanceId,
    ClaimGenerator,
    Regex,
    CawgAuthor,
    CawgPersonIdentifier,
}

// This is not used in the current implementation
/*
#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    #[serde(flatten)]
    manifest: ManifestDefinition,
    // This is not used in the current implementation
    // allows adding ingredients with file paths
    // ingredient_paths: Option<Vec<PathBuf>>,
}
*/

#[derive(Clone, Debug)]
enum TrustResource {
    File(PathBuf),
    Url(Url),
}

fn parse_resource_string(s: &str) -> Result<TrustResource> {
    if let Ok(url) = s.parse::<Url>() {
        Ok(TrustResource::Url(url))
    } else {
        let p = PathBuf::from_str(s)?;

        Ok(TrustResource::File(p))
    }
}

// We only construct one per invocation, not worth shrinking this.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    /// Sub-command to configure trust store options, "trust --help for more details"
    Trust {
        /// URL or path to file containing list of trust anchors in PEM format
        #[arg(long = "trust_anchors", env="C2PATOOL_TRUST_ANCHORS", value_parser = parse_resource_string)]
        trust_anchors: Option<TrustResource>,

        /// URL or path to file containing specific manifest signing certificates in PEM format to implicitly trust
        #[arg(long = "allowed_list", env="C2PATOOL_ALLOWED_LIST", value_parser = parse_resource_string)]
        allowed_list: Option<TrustResource>,

        /// URL or path to file containing configured EKUs in Oid dot notation
        #[arg(long = "trust_config", env="C2PATOOL_TRUST_CONFIG", value_parser = parse_resource_string)]
        trust_config: Option<TrustResource>,
    },
    /// Sub-command to add manifest to fragmented BMFF content
    ///
    /// The init path can be a glob to process entire directories of content, for example:
    ///
    /// c2patool -m test2.json -o /my_output_folder "/my_renditions/**/my_init.mp4" fragment --fragments_glob "myfile_abc*[0-9].m4s"
    ///
    /// Note: the glob patterns are quoted to prevent shell expansion.
    Fragment {
        /// Glob pattern to find the fragments of the asset. The path is automatically set to be the same as
        /// the init segment.
        ///
        /// The fragments_glob pattern should only match fragment file names not the full paths (e.g. "myfile_abc*[0-9].m4s"
        /// to match [myfile_abc1.m4s, myfile_abc2180.m4s, ...] )
        #[arg(long = "fragments_glob", verbatim_doc_comment)]
        fragments_glob: Option<PathBuf>,
    },
}

// define the command line options
#[derive(Parser, Debug)]
#[command(
    name = "c2pa-attacks",
    author,
    version,
    about = "A tool that can create C2PA manifests for the purposes of security testing.",
    after_help = "CAWG support covers metadata assertions protected by the C2PA manifest signature. \
                  Creating separately signed CAWG Identity assertions is not supported.",
    arg_required_else_help = true
)]
struct CliArgs {
    /// The path for the original asset image
    #[arg(required = true)]
    path: PathBuf,

    /// Path to manifest definition JSON file
    #[arg(
        short = 'm',
        long = "manifest",
        required_unless_present = "config",
        conflicts_with = "config"
    )]
    manifest_file: Option<PathBuf>,

    /// Path to the output folder and base file name for the output
    #[arg(short = 'o', required = true)]
    output: Option<PathBuf>,

    /// Target to mutate; use regex and a JSON template for arbitrary CAWG metadata.
    /// author/person_identifier retain legacy CreativeWork behavior.
    #[arg(short = 't', long, value_enum)]
    target: Target,

    /// The file containing the attack strings to use
    #[arg(short = 'a', required = true)]
    attack_file: String,

    /// Path to a parent file
    #[clap(short, long)]
    #[arg(short = 'p')]
    parent: Option<PathBuf>,

    /// Manifest definition passed as a JSON string
    #[arg(short = 'c', long, conflicts_with = "manifest_file")]
    config: Option<String>,

    /// Display detailed C2PA-formatted manifest data
    #[arg(short = 'd')]
    detailed: bool,

    /// Force overwriting of any pre-existing output files
    #[arg(short = 'f')]
    force: bool,

    /// Display verbose output
    #[arg(short = 'v')]
    verbose: bool,

    // Trust sub-command
    #[command(subcommand)]
    command: Option<Commands>,

    /// Do not perform validation of signature after signing.
    #[clap(long = "no_signing_verify")]
    no_signing_verify: bool,

    // TODO: ideally this would be called config, not to be confused with the other config arg
    /// Path to the settings file in JSON or TOML.
    ///
    /// By default the settings file is read from `$XDG_CONFIG_HOME/c2pa/c2pa.toml`.
    #[clap(
        long,
        env = "C2PATOOL_SETTINGS",
        default_value = default_settings_path().into_os_string()
    )]
    settings: PathBuf,
}

fn default_settings_path() -> PathBuf {
    let strategy = etcetera::choose_base_strategy().unwrap();
    let mut path = strategy.config_dir();
    path.push("c2pa");
    path.push("c2pa.toml");
    path
}

#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    // Flattened into the JSON root; the field is not read directly after deserialize.
    #[serde(flatten)]
    _manifest: ManifestDefinition,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// Convert certain errors to output messages.
fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {}", name),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
    }
}

// adds an ingredient, from a file, folder or json definition
fn add_ingredient(builder: &mut Builder, path: &Path, is_parent: bool) -> Result<()> {
    // if the path is a folder, look for ingredient.json
    let mut path_buf = PathBuf::from(path);
    let path = if path.is_dir() {
        path_buf = path_buf.join("ingredient.json");
        path_buf.as_path()
    } else {
        path
    };
    if path.extension() == Some(std::ffi::OsStr::new("json")) {
        // ingredient is a json file, load it directly and set the base path for any resources
        let json = std::fs::read_to_string(path)?;
        let mut ingredient: Ingredient = serde_json::from_slice(json.as_bytes())?;
        if let Some(base) = path.parent() {
            ingredient.resources_mut().set_base_path(base);
        }
        if is_parent {
            ingredient.set_relationship(c2pa::Relationship::ParentOf);
        }
        builder.add_ingredient(ingredient.clone());
        Ok(())
    } else {
        // ingredient is a file, load it as an ingredient with a relationship
        let mut file = File::open(path)?;
        let format = format_from_path(path)
            .ok_or_else(|| anyhow!("Could not determine format from path: {:?}", path))?;
        let json = json!({
            "relationship": if is_parent { c2pa::Relationship::ParentOf } else { c2pa::Relationship::ComponentOf },
        }).to_string();
        builder.add_ingredient_from_stream(json, &format, &mut file)?;
        Ok(())
    }
}

// This function is used to load a trust resource from a file for trust_anchors, allowed_list, or trust_config.
fn load_trust_resource(resource: &TrustResource) -> Result<String> {
    match resource {
        TrustResource::File(path) => {
            let data = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read trust resource from path: {path:?}"))?;

            Ok(data)
        }
        TrustResource::Url(url) => {
            #[cfg(not(target_os = "wasi"))]
            let data = reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read trust resource from URL: {url}"))?;

            #[cfg(target_os = "wasi")]
            let data = blocking_get(&url.to_string())?;
            Ok(data)
        }
    }
}

/// Load trust PEM/config sidecars from the same directory as `--settings`, if present.
/// Returns whether any trust material was applied (for enabling `verify_trust`).
fn apply_trust_sidecars(settings: &mut Settings, settings_path: &Path) -> Result<bool> {
    let Some(dir) = settings_path.parent() else {
        return Ok(false);
    };
    let mut applied = false;

    let official = dir.join(SIDECAR_TRUST_LIST_PEM);
    if official.exists() {
        let data = fs::read_to_string(&official)
            .with_context(|| format!("read trust sidecar {}", official.display()))?;
        settings
            .trust
            .anchors
            .get_or_insert_with(Vec::new)
            .push(TrustAnchor {
                trust_anchors: data,
                ..Default::default()
            });
        applied = true;
    }

    let legacy_pem = dir.join(SIDECAR_TRUST_LIST_LEGACY_PEM);
    if legacy_pem.exists() {
        let data = fs::read_to_string(&legacy_pem)
            .with_context(|| format!("read legacy trust sidecar {}", legacy_pem.display()))?;
        settings
            .trust
            .anchors
            .get_or_insert_with(Vec::new)
            .push(TrustAnchor {
                trust_anchors: data,
                ..Default::default()
            });
        applied = true;
    }

    let store_cfg = dir.join(SIDECAR_TRUST_STORE_CFG);
    if store_cfg.exists() {
        let data = fs::read_to_string(&store_cfg)
            .with_context(|| format!("read trust sidecar {}", store_cfg.display()))?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                trust_config = data
            }
            .to_string(),
            "toml",
        )?;
        applied = true;
    }

    let allowed = dir.join(SIDECAR_TRUST_ALLOWED);
    if allowed.exists() {
        let data = fs::read_to_string(&allowed)
            .with_context(|| format!("read trust sidecar {}", allowed.display()))?;
        settings
            .trust
            .anchors
            .get_or_insert_with(Vec::new)
            .push(TrustAnchor {
                allowed_list: Some(data),
                ..Default::default()
            });
        applied = true;
    }

    Ok(applied)
}

// This function will handle any specific trust settings that are provided via the command line.
fn configure_sdk(args: &CliArgs) -> Result<Settings> {
    let mut settings = if args.settings.exists() {
        Settings::new().with_file(&args.settings)?
    } else {
        Settings::default()
    };

    let sidecar_trust = apply_trust_sidecars(&mut settings, &args.settings)?;

    let mut enable_trust_checks = sidecar_trust;

    if let Some(Commands::Trust {
        trust_anchors,
        allowed_list,
        trust_config,
    }) = &args.command
    {
        if let Some(trust_list) = &trust_anchors {
            debug!("Using trust anchors from {trust_list:?}");

            let data = load_trust_resource(trust_list)?;
            settings
                .trust
                .anchors
                .get_or_insert_with(Vec::new)
                .push(TrustAnchor {
                    trust_anchors: data,
                    ..Default::default()
                });

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = &allowed_list {
            debug!("Using allowed list from {allowed_list:?}");

            let data = load_trust_resource(allowed_list)?;
            settings
                .trust
                .anchors
                .get_or_insert_with(Vec::new)
                .push(TrustAnchor {
                    allowed_list: Some(data),
                    ..Default::default()
                });

            enable_trust_checks = true;
        }

        if let Some(trust_config) = &trust_config {
            debug!("Using trust config from {trust_config:?}");

            let data = load_trust_resource(trust_config)?;
            settings.update_from_str(
                &toml::toml! {
                    [trust]
                    trust_config = data
                }
                .to_string(),
                "toml",
            )?;

            enable_trust_checks = true;
        }
    }

    // If trust material came from CLI or sidecars, enable trust checks (cannot disable defaults).
    if enable_trust_checks {
        settings.update_from_str(
            &toml::toml! {
                [verify]
                verify_trust = true
            }
            .to_string(),
            "toml",
        )?;
    }

    Ok(settings)
}

// The file containing the injection attacks needs to be read line-by-line
// This will return an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn escape_malicious_string(mal_string: String) -> Result<String> {
    let encoded = serde_json::to_string(&mal_string)?;
    // Remove only the enclosing quotes; retain all JSON string escaping.
    Ok(encoded[1..encoded.len() - 1].to_owned())
}

// Remove any pre-existing assertion of the same type as the malicious assertion.
fn remove_existing_assertion(
    orig_json: String,
    field_type: String,
    verbose: bool,
) -> Result<Map<String, Value>> {
    let mut map: Map<String, Value> = serde_json::from_str(&orig_json)?;
    if !matches!(field_type.as_str(), "author" | "person_identifier") {
        return Ok(map);
    }
    if let Some(assertions) = map.get_mut("assertions") {
        let assertions = assertions
            .as_array_mut()
            .context("assertions must be an array")?;
        assertions.retain(|assertion| {
            let drop = assertion["label"] == LEGACY_CREATIVE_WORK
                && (assertion["data"].get("author").is_some()
                    || (field_type == "person_identifier"
                        && assertion["data"].get("creator").is_some()));
            if drop && verbose {
                eprintln!("Dropping Creative Work from original source");
            }
            !drop
        });
    }
    Ok(map)
}

// For attack types of author or person_identifier, we will create a new malicious
// Creative Work assertion with the appropriate malicous fields.
fn malicious_creative_work(field_type: &str, mal_string: &str) -> Option<Value> {
    let mut person = json!({"@type": "Person", "name": mal_string});
    if field_type == "person_identifier" {
        person["name"] = json!("Malicious User");
        person["identifier"] = json!(mal_string);
        person["@id"] = json!([mal_string]);
    } else if field_type != "author" {
        return None;
    }
    let mut assertion = json!({
        "@context": "http://schema.org/",
        "@type": "CreativeWork",
        "author": [person.clone()]
    });
    if field_type == "person_identifier" {
        assertion["creator"] = person;
    }
    Some(assertion)
}

fn mutate_cawg_metadata(
    definition: &mut Map<String, Value>,
    field_type: &str,
    mal_string: &str,
) -> Result<()> {
    let assertions = definition
        .entry("assertions")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("assertions must be an array")?;
    let mut candidate = None;
    for (index, assertion) in assertions.iter().enumerate() {
        if let Some(label) = assertion["label"].as_str() {
            let (base, version, _) = labels::parse_label(label);
            if base == labels::CAWG_METADATA {
                if version != 1 {
                    bail!("Unsupported CAWG metadata version; use a tailored -t regex template");
                }
                if candidate.replace(index).is_some() {
                    bail!("Multiple CAWG metadata assertions; use a tailored -t regex template");
                }
            }
        }
    }
    let index = match candidate {
        Some(index) => index,
        None => {
            assertions.push(json!({"label": labels::CAWG_METADATA, "data": {}}));
            assertions.len() - 1
        }
    };
    let assertion = &mut assertions[index];
    let data = assertion["data"]
        .as_object_mut()
        .context("CAWG metadata data must be an object")?;
    let context = data
        .entry("@context")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("CAWG @context must be an object; use a tailored -t regex template")?;
    if let Some(namespace) = context.get("schema") {
        if namespace != SCHEMA_NAMESPACE {
            bail!("Conflicting schema namespace; use a tailored -t regex template");
        }
    } else {
        context.insert("schema".to_owned(), json!(SCHEMA_NAMESPACE));
    }
    let authors = data
        .entry("schema:author")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("schema:author must be an array; use a tailored -t regex template")?;
    if authors.is_empty() {
        authors.push(json!({"@type": "schema:Person"}));
    }
    let person = authors[0]
        .as_object_mut()
        .context("first schema:author must be a person object")?;
    match person.get("@type") {
        Some(person_type) if person_type != "schema:Person" => {
            bail!("First schema:author must have type schema:Person; use a tailored -t regex template");
        }
        None => {
            person.insert("@type".to_owned(), json!("schema:Person"));
        }
        _ => {}
    }
    let property = if field_type == "cawg_author" {
        "schema:name"
    } else {
        person
            .entry("schema:name")
            .or_insert_with(|| json!("Malicious User"));
        "schema:identifier"
    };
    person.insert(property.to_owned(), json!(mal_string));
    let metadata = Metadata::new(labels::CAWG_METADATA, &serde_json::to_string(data)?)?;
    if !metadata.is_valid() {
        bail!("Invalid CAWG metadata namespaces; use a tailored -t regex template");
    }
    assertion["data"] = serde_json::to_value(metadata)?;
    assertion["kind"] = serde_json::to_value(ManifestAssertionKind::Json)?;
    Ok(())
}

/**
 * This function is used to create the output file name for each mutation of the base file.
 *
 * The output files are of the format:
 *
 * {targeted_field}_{injection_file_name}_{line_no_from_injection_file}_{original_name_of_input_file}
 *
 * The line numbers from the injection file start at zero.
 */
fn create_output_file_name(args: &CliArgs, field_type: String, loop_index: &i64) -> String {
    let output = args.output.clone().unwrap();
    let temp_path = args.attack_file.clone();
    let attack_file_path = Path::new(&temp_path);
    let attack_file_name = attack_file_path.file_stem().unwrap();

    let filename = output.file_name();
    let orig_file = filename.unwrap().to_str();
    let mut new_filename = field_type;
    new_filename.push('_');
    new_filename.push_str(attack_file_name.to_str().unwrap());
    new_filename.push('_');
    new_filename.push_str(loop_index.to_string().as_str());
    new_filename.push('_');
    new_filename.push_str(orig_file.unwrap());

    new_filename
}

// This function will create the malicious output files.
//
// The output files are of the format:
//
// {targeted_field}_{line_no_from_injection_file}_{original_name_of_input_file}
//
// The line numbers from the injection file start at zero.
fn output_file(
    args: &CliArgs,
    builder: &mut Builder,
    sign_config: &SignConfig,
    field_type: String,
    mal_string: &String,
    loop_index: &i64,
    testing_mode: bool,
) -> Result<()> {
    if let Some(new_assertion) = malicious_creative_work(&field_type, mal_string) {
        builder.add_assertion_json(LEGACY_CREATIVE_WORK, &new_assertion)?;
    }

    if field_type.eq("title") {
        builder.definition.title = Some(mal_string.to_owned());
    }

    if field_type.eq("claim_generator") {
        builder.set_claim_generator_info(ClaimGeneratorInfo::new(mal_string.to_owned()));
    }

    // This is currently data validated by the SDK to ensure that it is a valid GUID.
    // https://github.com/contentauth/c2pa-rs/blob/main/sdk/src/claim.rs#L429
    // https://docs.rs/uuid/latest/src/uuid/parser.rs.html#98-100
    if field_type.eq("label") {
        builder.definition.label = Some(mal_string.to_owned());
    }

    // This is currently ignored by the SDK and not used in the manifest.
    // The SDK calculates the value at signing time.
    // https://github.com/contentauth/c2pa-rs/blob/main/sdk/src/builder.rs#L1125
    if field_type.eq("format") {
        builder.set_format(mal_string.to_owned());
        // builder.definition.format = mal_string.to_owned();
    }

    if field_type.eq("vendor") {
        builder.definition.vendor = Some(mal_string.to_owned());
    }

    // This is currently ignored by the SDK and not used in the manifest.
    // The SDK generates the value at signing time.
    // https://github.com/contentauth/c2pa-rs/blob/main/sdk/src/builder.rs#L993
    if field_type.eq("instance_id") {
        builder.definition.instance_id = mal_string.to_owned();
    }

    if let Some(mut output) = args.output.clone() {
        if output.extension() != args.path.extension() {
            bail!("output type must match source type");
        }

        if output.file_name().is_none() {
            bail!("Missing filename on output");
        }
        if output.extension().is_none() {
            bail!("Missing extension output");
        }

        let new_filename = create_output_file_name(args, field_type, loop_index);
        output.pop();
        output.push(new_filename);

        if output.exists() {
            if args.force {
                if args.verbose {
                    println!("Manually removing file: {:?}", output.to_str());
                }
                remove_file(&output)?;
            } else {
                bail!("Output already exists; use -f/force to force write");
            }
        }

        if args.verbose {
            println!("File to be created: {:?}", output.to_str());
        }

        let signer = sign_config.signer()?;

        if testing_mode {
            return Ok(());
        }

        // create any needed folders for the output path (embed should do this)
        let mut output_dir = PathBuf::from(&output);
        output_dir.pop();
        create_dir_all(&output_dir)?;

        if let Err(error) = builder.sign_file(signer.as_ref(), &args.path, &output) {
            if output.exists() {
                remove_file(&output).context("removing partial signed output")?;
            }
            return Err(signing_error(error, args.target)).context("signing file");
        }

        // generate a report on the output file
        let reader = match Reader::from_shared_context(builder.context()).with_file(&output) {
            Ok(reader) => reader,
            Err(error) => {
                if args.target == Target::Vendor
                    && mal_string.contains('\0')
                    && matches!(&error, Error::JumbfParseError(parse) if parse.to_string() == "unexpected end of file")
                {
                    remove_file(&output).context("removing unreadable vendor attack output")?;
                    return Err(AttackRejected(error)).context("reading signed vendor attack");
                }
                return Err(special_errs(error));
            }
        };
        if args.verbose {
            if args.detailed {
                println!("{reader:#?}");
            } else {
                println!("{reader}")
            }
        }
    }
    Ok(())
}

// Create the malicious manifest containing the chosen attack string.
fn create_manifest_def_as_string(
    json: String,
    field_type: String,
    mal_string: String,
    verbose: bool,
) -> Result<String> {
    // Define the string that the regex mode will use to find and use to subsitute injection strings
    let re = Regex::new("C2PA_ATTACK")?;

    if re.is_match(json.as_str()) && field_type.eq("regex") {
        let escaped_string = escape_malicious_string(mal_string)?;

        let after = re.replace_all(json.as_str(), NoExpand(&escaped_string));
        serde_json::from_str::<Value>(&after).context("substituting manifest template")?;

        Ok(after.to_string())
    } else {
        let mut new_map = remove_existing_assertion(json, field_type.clone(), verbose)?;
        if matches!(
            field_type.as_str(),
            "cawg_author" | "cawg_person_identifier"
        ) {
            mutate_cawg_metadata(&mut new_map, &field_type, &mal_string)
                .with_context(|| format!("preparing {field_type} attack"))?;
        }
        Ok(serde_json::to_string(&new_map)?)
    }
}

// Create the malicious manifest containing the chosen attack string as a Serde JSON object.
// This is not used in the current implementation
/*
fn create_manifest_def(
    json: String,
    field_type: String,
    mal_string: String,
    verbose: bool,
) -> Result<ManifestDef> {
    // Define the string that the regex mode will use to find and use to subsitute injection strings
    let re: Regex = Regex::new(r"(?P<a>C2PA_ATTACK)").unwrap();

    if re.is_match(json.as_str()) && field_type.eq("regex") {
        let after: String = create_manifest_def_as_string(json, field_type, mal_string, verbose)?;
        Ok(serde_json::from_str(&after)?)
    } else {
        let new_string: String =
            create_manifest_def_as_string(json, field_type, mal_string, verbose)?;
        Ok(serde_json::from_slice(new_string.as_bytes())?)
    }
}
*/

// This function will create the individual malicious files (except when in test mode)
// It is called within the loop in main which is reading each line of the malicious inputs
fn create_file(
    field_type: String,
    loop_index: &mut i64,
    mal_string: String,
    args: &CliArgs,
    testing_mode: bool,
) -> Result<()> {
    let escaped_string = mal_string.clone();

    let config = args.config.clone();

    // let is_fragment = matches!(
    //    &args.command,
    //    Some(Commands::Fragment { fragments_glob: _ })
    // );

    // configure the SDK
    let settings = configure_sdk(args).context("Could not configure c2pa-rs")?;
    let context = Arc::new(C2paContext::new().with_settings(&settings)?);

    // if we have a manifest config, process it
    if args.manifest_file.is_some() || config.is_some() {
        // read the json from file or config, and get base path if from file
        let (json, base_path) = match args.manifest_file.as_deref() {
            Some(manifest_path) => {
                if !manifest_path.exists() {
                    return Err(anyhow!("ERROR: Manifest file does not exist!"));
                }

                let base_path = std::fs::canonicalize(manifest_path)?
                    .parent()
                    .map(|p| p.to_path_buf());
                (std::fs::read_to_string(manifest_path)?, base_path)
            }
            None => (
                args.config.clone().unwrap_or_default(),
                Some(std::env::current_dir().context("resolving inline manifest base path")?),
            ),
        };

        // read the signing information from the manifest definition
        let mut sign_config = SignConfig::from_json(&json)?;

        // This is not used in the current implementation
        /*
        let manifest_def: ManifestDef = match create_manifest_def(
            json.clone(),
            field_type.clone(),
            mal_string.clone(),
            args.verbose,
        ) {
            Ok(_v) => {
                // println!("Success");
                _v
            }
            Err(e) => {
                println!("Error: Skipping creating malicious file with {mal_string} due to: {e:?}");
                return Err(e);
            }
        };
        */

        let new_json: String = create_manifest_def_as_string(
            json.clone(),
            field_type.clone(),
            mal_string.clone(),
            args.verbose,
        )?;

        let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
        let mut builder = Builder::from_shared_context(&context).with_definition(&new_json)?;

        // The manfifest approach is no longer used because sign_file() was deprecated.
        // Instead, we will use the builder to create the manifest.
        // This section is kept for reference and in case we need to revert to the manifest approach.
        /*
        let mut manifest = manifest_def.manifest;

        // add claim_tool generator so we know this was created using this tool
        let mut tool_generator = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
        tool_generator.set_version(env!("CARGO_PKG_VERSION"));
        if !manifest.claim_generator_info.is_empty()
            || manifest.claim_generator_info[0].name == "c2pa-rs"
        {
            manifest.claim_generator_info = vec![tool_generator];
        } else {
            manifest.claim_generator_info.insert(1, tool_generator);
        }
        */
        if let Some(base) = base_path.as_ref() {
            builder.set_base_path(base);
            sign_config.set_base_path(base);
        }

        // Add any ingredients specified as file paths
        if let Some(paths) = manifest_def.ingredient_paths {
            for mut path in paths {
                // ingredient paths are relative to the manifest path
                if let Some(base) = &base_path {
                    if !(path.is_absolute()) {
                        path = base.join(&path)
                    }
                }
                add_ingredient(&mut builder, &path, false)?;
            }
        }

        if let Some(parent_path) = &args.parent {
            add_ingredient(&mut builder, parent_path, true)?
        }

        output_file(
            args,
            &mut builder,
            &sign_config,
            field_type.clone(),
            &escaped_string,
            loop_index,
            testing_mode,
        )?;
        *loop_index += 1;
    }
    Ok(())
}

fn main() -> Result<ExitCode> {
    let args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();

    let target_value = args
        .target
        .to_possible_value()
        .context("Missing target name")?;
    let field_type = target_value.get_name().to_owned();
    if args.target == Target::Label {
        eprintln!(
            "WARNING: The label target requires a valid GUID format. \
             Arbitrary strings are rejected by the SDK."
        );
    }
    if matches!(args.target, Target::Author | Target::PersonIdentifier) {
        eprintln!(
            "WARNING: {field_type} creates deprecated CreativeWork metadata. Use \
             cawg_{field_type} for CAWG metadata, or -t regex with a JSON template."
        );
    }

    if field_type.eq("instance_id") || field_type.eq("format") {
        println!(
            "WARNING: Instance ID and format values currently cannot be overridden by this version of the tool. \
             Consider using the 0.0.2 version of the tool instead."
        );
    }

    // Set to track the current line in the injection file.
    let mut loop_index = 0;

    // If we can successfully read the injection file path
    if let Ok(lines) = read_lines(args.attack_file.clone()) {
        // Consumes the iterator, returns an (Optional) String
        let mut failures = 0;
        let mut rejected = 0;
        for mal_string in lines {
            let mal_string = mal_string.context("reading attack string")?;
            let result = create_file(
                field_type.clone(),
                &mut loop_index,
                mal_string,
                &args,
                false,
            );

            match result {
                Ok(_v) => {}
                Err(e) => {
                    eprintln!("Failed to create file: {loop_index}");
                    eprintln!("Failed due to error: {e:?}");
                    if e.downcast_ref::<AttackRejected>().is_some() {
                        rejected += 1;
                    } else {
                        failures += 1;
                    }
                    loop_index += 1;
                }
            }
        }
        if failures > 0 {
            bail!("Failed to create {failures} attack file(s)");
        }
        if rejected > 0 {
            eprintln!("SDK rejected {rejected} attack payload(s); all payloads were attempted");
            return Ok(ExitCode::from(ATTACK_REJECTED_EXIT_CODE));
        }
    } else {
        bail!("ERROR: Could not find the attack injection file!");
    }

    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::PathBuf;

    use super::*;
    use crate::CliArgs;

    fn mutated(template: &str, target: &str, payload: &str) -> Value {
        serde_json::from_str(
            &create_manifest_def_as_string(
                template.to_owned(),
                target.to_owned(),
                payload.to_owned(),
                false,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn cli_args(extra: &[&str]) -> Result<CliArgs, clap::Error> {
        let mut args = vec![
            "c2pa-attacks",
            "sample/image.jpg",
            "-o",
            "signed.jpg",
            "-a",
            "attacks/xss.attack",
        ];
        args.extend_from_slice(extra);
        CliArgs::try_parse_from(args)
    }

    #[test]
    fn test_cawg_cli_configuration_and_help() {
        use clap::CommandFactory;

        let from_file = cli_args(&[
            "--manifest",
            "sample/cawg_metadata.json",
            "--target",
            "cawg_author",
        ])
        .unwrap();
        assert_eq!(from_file.target, Target::CawgAuthor);
        let inline = cli_args(&["--config", "{}", "-t", "cawg_person_identifier"]).unwrap();
        assert_eq!(inline.target, Target::CawgPersonIdentifier);
        assert!(inline.manifest_file.is_none());
        assert!(cli_args(&["-t", "regex"]).is_err());
        assert!(cli_args(&["-m", "test.json", "-c", "{}", "-t", "regex"]).is_err());
        assert!(cli_args(&["-m", "test.json", "-t", "unknown"]).is_err());
        assert!(cli_args(&["-m", "test.json"]).is_err());
        for legacy in ["author", "person_identifier", "title", "regex"] {
            assert!(cli_args(&["-m", "test.json", "-t", legacy]).is_ok());
        }
        let help = CliArgs::command().render_long_help().to_string();
        assert!(
            help.contains("Creating separately signed CAWG Identity assertions is not supported.")
        );
        for name in [
            "--target",
            "--manifest",
            "--config",
            "cawg_author",
            "cawg_person_identifier",
        ] {
            assert!(help.contains(name), "{help}");
        }
    }

    #[test]
    fn test_cawg_presets_preserve_other_data() {
        let template = json!({
            "claim_version": 2,
            "title": "Keep",
            "assertions": [
                {"label": "my.assertion", "data": {"other": "Keep"}},
                {"label": "cawg.metadata__1", "created": true, "data": {
                    "@context": {"schema": SCHEMA_NAMESPACE, "dc": "http://purl.org/dc/elements/1.1/"},
                    "dc:title": "Keep",
                    "schema:author": [
                        {"@type": "schema:Person", "schema:name": "First", "schema:identifier": "First ID"},
                        {"@type": "schema:Person", "schema:name": "Second"}
                    ]
                }},
                {"label": "cawg.training-mining", "data": {"entries": {}}}
            ]
        });
        for (target, property) in [
            ("cawg_author", "schema:name"),
            ("cawg_person_identifier", "schema:identifier"),
        ] {
            let payload = "literal $1 \"value\" \\ \u{0} \u{00e9}";
            let result = mutated(&template.to_string(), target, payload);
            let mut expected = template.clone();
            expected["assertions"][1]["data"]["schema:author"][0][property] = json!(payload);
            expected["assertions"][1]["kind"] = json!("Json");
            assert_eq!(result, expected);
        }
        let added = mutated(
            r#"{"assertions":[]}"#,
            "cawg_person_identifier",
            "not a URL",
        );
        assert_eq!(added["assertions"][0]["label"], labels::CAWG_METADATA);
        assert_eq!(
            added["assertions"][0]["data"]["schema:author"][0]["schema:identifier"],
            "not a URL"
        );
        assert_eq!(
            added["assertions"][0]["data"]["schema:author"][0]["schema:name"],
            "Malicious User"
        );
    }

    #[test]
    fn test_cawg_presets_reject_ambiguous_or_incompatible_input() {
        for template in [
            json!({"assertions": [
                {"label":"cawg.metadata","data":{}},
                {"label":"cawg.metadata__1","data":{}}
            ]}),
            json!({"assertions":[{"label":"cawg.metadata.v2","data":{}}]}),
            json!({"assertions":[{"label":"cawg.metadata","data":{
                "@context":{"schema":"https://example.com/conflict"}
            }}]}),
            json!({"assertions":[{"label":"cawg.metadata","data":{
                "schema:author":"not an array"
            }}]}),
            json!({"assertions":[{"label":"cawg.metadata","data":{
                "schema:author":[{"@type":"schema:Organization"}]
            }}]}),
        ] {
            let error = create_manifest_def_as_string(
                template.to_string(),
                "cawg_author".to_owned(),
                "payload".to_owned(),
                false,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("regex"), "{error:#}");
        }
    }

    #[test]
    fn test_cawg_templates_preserve_literal_payload_and_support_other_schemas() {
        let template = json!({
            "assertions": [{
                "label": "cawg.metadata", "kind": "Json", "data": {
                    "@context": {"dc":"http://purl.org/dc/elements/1.1/"},
                    "dc:creator": ["C2PA_ATTACK", "Other"],
                    "dc:description": {"nested": "prefix C2PA_ATTACK suffix"},
                    "C2PA_ATTACK": "Keep"
                }
            }]
        });
        for payload in ["$1 ${name} $$", "\"quote\" \\path\\", "\u{0}\t\n\u{00e9}"] {
            let result = mutated(&template.to_string(), "regex", payload);
            let data = &result["assertions"][0]["data"];
            assert_eq!(data["dc:creator"], json!([payload, "Other"]));
            assert_eq!(
                data["dc:description"]["nested"],
                format!("prefix {payload} suffix")
            );
            assert_eq!(data[payload], "Keep");
            assert_eq!(
                data["@context"],
                template["assertions"][0]["data"]["@context"]
            );
        }
        let unchanged = json!({"title":"No marker","assertions":[]});
        assert_eq!(mutated(&unchanged.to_string(), "regex", "$1"), unchanged);
    }

    #[test]
    fn test_legacy_creative_work_output_and_cleanup() {
        let payload = "\"name\"\\";
        assert_eq!(
            malicious_creative_work("author", payload).unwrap(),
            json!({
                "@context":"http://schema.org/", "@type":"CreativeWork",
                "author":[{"@type":"Person","name":payload}]
            })
        );
        let person = json!({
            "@type":"Person","name":"Malicious User","identifier":payload,"@id":[payload]
        });
        assert_eq!(
            malicious_creative_work("person_identifier", payload).unwrap(),
            json!({
                "@context":"http://schema.org/","@type":"CreativeWork",
                "author":[person.clone()],"creator":person
            })
        );
        let template = include_str!("../sample/test.json");
        let cleaned = mutated(template, "author", payload);
        assert!(cleaned["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|assertion| assertion["label"] != LEGACY_CREATIVE_WORK));
        assert_eq!(
            mutated(template, "title", payload),
            serde_json::from_str::<Value>(template).unwrap()
        );
        let ca = mutated(template, "cawg_author", payload);
        assert_eq!(ca["assertions"][0]["label"], LEGACY_CREATIVE_WORK);
    }

    #[test]
    fn test_cawg_file_and_inline_resource_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let template = temp.path().join("template.json");
        fs::write(
            temp.path().join("es256_private.key"),
            include_bytes!("../sample/es256_private.key"),
        )
        .unwrap();
        fs::write(
            temp.path().join("es256_certs.pem"),
            include_bytes!("../sample/es256_certs.pem"),
        )
        .unwrap();
        fs::write(&template, include_str!("../sample/cawg_author_regex.json")).unwrap();
        let mut file_args = cli_args(&["-m", template.to_str().unwrap(), "-t", "regex"]).unwrap();
        file_args.settings = temp.path().join("settings.toml");
        file_args.output = Some(temp.path().join("output.jpg"));
        let mut index = 0;
        create_file(
            "regex".to_owned(),
            &mut index,
            "$1".to_owned(),
            &file_args,
            true,
        )
        .unwrap();
        assert_eq!(index, 1);

        let mut definition: Value =
            serde_json::from_str(include_str!("../sample/cawg_author_regex.json")).unwrap();
        definition["private_key"] = json!(temp.path().join("es256_private.key"));
        definition["sign_cert"] = json!(temp.path().join("es256_certs.pem"));
        let mut inline_args = cli_args(&["-c", &definition.to_string(), "-t", "regex"]).unwrap();
        inline_args.settings = file_args.settings.clone();
        inline_args.output = file_args.output.clone();
        create_file(
            "regex".to_owned(),
            &mut index,
            "$1".to_owned(),
            &inline_args,
            true,
        )
        .unwrap();
        assert_eq!(index, 2);
    }

    #[test]
    fn test_cawg_and_legacy_signed_round_trip() {
        // Existing public development fixtures; no timestamp request or external signer.
        let signer = c2pa::create_signer::from_keys(
            include_bytes!("../sample/es256_certs.pem"),
            include_bytes!("../sample/es256_private.key"),
            c2pa::SigningAlg::Es256,
            None,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut settings = Settings::new();
        // Trust only the existing development fixture locally; do not bypass signature checks.
        settings
            .update_from_str(
                &json!({
                    "trust": {"anchors": [{
                        "trust_anchors": "",
                        "trust_kind": "manifest",
                        "allowed_list": include_str!("../sample/es256_certs.pem")
                    }]},
                    "verify": {"verify_trust": true}
                })
                .to_string(),
                "json",
            )
            .unwrap();
        let context = Arc::new(C2paContext::new().with_settings(&settings).unwrap());
        let payload = "literal $1 \"name\" \\path\\ \u{00e9}";
        for (target, label, property) in [
            ("cawg_author", labels::CAWG_METADATA, "schema:name"),
            (
                "cawg_person_identifier",
                labels::CAWG_METADATA,
                "schema:identifier",
            ),
            ("author", LEGACY_CREATIVE_WORK, "name"),
            ("person_identifier", LEGACY_CREATIVE_WORK, "identifier"),
            ("regex", labels::CAWG_METADATA, "schema:name"),
        ] {
            let template = if label == LEGACY_CREATIVE_WORK {
                include_str!("../sample/test.json")
            } else if target == "regex" {
                include_str!("../sample/cawg_author_regex.json")
            } else {
                include_str!("../sample/cawg_metadata.json")
            };
            let definition = create_manifest_def_as_string(
                template.to_owned(),
                target.to_owned(),
                payload.to_owned(),
                false,
            )
            .unwrap();
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(&definition)
                .unwrap();
            if let Some(legacy) = malicious_creative_work(target, payload) {
                builder
                    .add_assertion_json(LEGACY_CREATIVE_WORK, &legacy)
                    .unwrap();
            }

            let output = temp.path().join(format!("{target}.jpg"));
            builder
                .sign_file(signer.as_ref(), "sample/image.jpg", &output)
                .unwrap();
            let reader = Reader::from_shared_context(&context)
                .with_file(&output)
                .unwrap();
            assert_eq!(reader.validation_state(), c2pa::ValidationState::Trusted);
            let assertions = reader.active_manifest().unwrap().assertions();
            let assertion = assertions
                .iter()
                .find(|assertion| labels::base(assertion.label()) == label)
                .unwrap();
            assert_eq!(assertion.kind(), &ManifestAssertionKind::Json);
            let data = assertion.value().unwrap();
            let authors = if label == LEGACY_CREATIVE_WORK {
                "author"
            } else {
                "schema:author"
            };
            assert_eq!(data[authors][0][property], payload);
            assert_eq!(
                assertions
                    .iter()
                    .filter(|assertion| labels::base(assertion.label()) == label)
                    .count(),
                1
            );
            if label == labels::CAWG_METADATA {
                assert!(assertions
                    .iter()
                    .all(|assertion| assertion.label() != LEGACY_CREATIVE_WORK));
            }
        }
    }

    #[test]
    fn test_sdk_trust_sidecars_preserve_configured_anchors() {
        let temp = tempfile::tempdir().unwrap();
        let original = TrustAnchor {
            trust_kind: c2pa::settings::TrustListKind::CAWG,
            trust_uri: Some("https://example.org/test-cawg-trust".to_owned()),
            ..Default::default()
        };
        let mut settings = Settings::new();
        settings.trust.anchors = Some(vec![original.clone()]);
        let settings_path = temp.path().join("settings.json");
        fs::write(&settings_path, serde_json::to_string(&settings).unwrap()).unwrap();
        let cert = include_str!("../sample/es256_certs.pem");
        for name in [
            SIDECAR_TRUST_LIST_PEM,
            SIDECAR_TRUST_LIST_LEGACY_PEM,
            SIDECAR_TRUST_ALLOWED,
        ] {
            fs::write(temp.path().join(name), cert).unwrap();
        }
        let mut args = cli_args(&["-m", "sample/cawg_metadata.json", "-t", "cawg_author"]).unwrap();
        args.settings = settings_path;
        let loaded = configure_sdk(&args).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded).unwrap()["verify"]["verify_trust"],
            true
        );
        let anchors = loaded.trust.anchors.as_ref().unwrap();
        assert_eq!(anchors.len(), 4);
        assert_eq!(anchors[0], original);
        assert_eq!(anchors[1].trust_anchors, cert);
        assert_eq!(anchors[2].trust_anchors, cert);
        assert_eq!(anchors[3].allowed_list.as_deref(), Some(cert));
        assert!(anchors[1..]
            .iter()
            .all(|anchor| anchor.trust_kind == c2pa::settings::TrustListKind::Manifest));
        C2paContext::new().with_settings(&loaded).unwrap();
    }

    #[test]
    fn test_sdk_trust_cli_uses_manifest_entries() {
        let temp = tempfile::tempdir().unwrap();
        let cert = include_str!("../sample/es256_certs.pem");
        let certificate_path = temp.path().join("certificate.pem");
        fs::write(&certificate_path, cert).unwrap();
        let mut args = cli_args(&["-m", "sample/cawg_metadata.json", "-t", "cawg_author"]).unwrap();
        args.settings = temp.path().join("settings.json");
        args.command = Some(Commands::Trust {
            trust_anchors: Some(TrustResource::File(certificate_path.clone())),
            allowed_list: Some(TrustResource::File(certificate_path)),
            trust_config: None,
        });
        let loaded = configure_sdk(&args).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded).unwrap()["verify"]["verify_trust"],
            true
        );
        let anchors = loaded.trust.anchors.as_ref().unwrap();
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].trust_anchors, cert);
        assert_eq!(anchors[1].allowed_list.as_deref(), Some(cert));
        assert!(anchors
            .iter()
            .all(|anchor| anchor.trust_kind == c2pa::settings::TrustListKind::Manifest));
        C2paContext::new().with_settings(&loaded).unwrap();
    }

    #[test]
    fn test_signing_rejection_classification_preserves_real_errors() {
        assert!(signing_error(
            Error::BadParam("invalid Claim GUID".to_owned()),
            Target::Label
        )
        .downcast_ref::<AttackRejected>()
        .is_some());
        for (error, target) in [
            (
                Error::BadParam("invalid Claim GUID".to_owned()),
                Target::Title,
            ),
            (
                Error::BadParam("invalid signing configuration".to_owned()),
                Target::Label,
            ),
            (Error::ClaimEncoding, Target::Title),
            (
                Error::IoError(io::Error::from(io::ErrorKind::PermissionDenied)),
                Target::Vendor,
            ),
        ] {
            assert!(signing_error(error, target)
                .downcast_ref::<AttackRejected>()
                .is_none());
        }
        for extra_failure in [None, Some("assertion.action.malformed")] {
            let mut failures = vec![json!({
                "code": "claim.malformed",
                "explanation": "claim box label invalid"
            })];
            if let Some(code) = extra_failure {
                failures.push(json!({"code": code}));
            }
            let validation = serde_json::from_value(json!({
                "activeManifest": {"success": [], "informational": [], "failure": failures}
            }))
            .unwrap();
            let error = signing_error(Error::InvalidManifest(Box::new(validation)), Target::Vendor);
            assert_eq!(
                error.downcast_ref::<AttackRejected>().is_some(),
                extra_failure.is_none()
            );
        }
    }

    #[test]
    fn test_sdk_rejected_payloads_remove_outputs_but_missing_input_is_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let mut args = cli_args(&["-m", "sample/cawg_metadata.json", "-t", "label"]).unwrap();
        args.settings = temp.path().join("settings.json");
        fs::write(
            &args.settings,
            json!({
                "trust": {"anchors": [{
                    "trust_anchors": "",
                    "trust_kind": "manifest",
                    "allowed_list": include_str!("../sample/es256_certs.pem")
                }]},
                "verify": {"verify_trust": true}
            })
            .to_string(),
        )
        .unwrap();
        args.output = Some(temp.path().join("output.jpg"));
        for (target, field, payload) in [
            (Target::Label, "label", "not-a-guid"),
            (Target::Vendor, "vendor", "Injected\0Null"),
        ] {
            args.target = target;
            let mut index = 0;
            let error = create_file(
                field.to_owned(),
                &mut index,
                payload.to_owned(),
                &args,
                false,
            )
            .unwrap_err();
            assert!(
                error.downcast_ref::<AttackRejected>().is_some(),
                "{error:#}; SDK variant: {:?}",
                error.downcast_ref::<Error>()
            );
            assert!(!temp
                .path()
                .join(create_output_file_name(&args, field.to_owned(), &0))
                .exists());
        }
        args.target = Target::Vendor;
        args.path = temp.path().join("missing.jpg");
        let error = create_file(
            "vendor".to_owned(),
            &mut 0,
            "payload".to_owned(),
            &args,
            false,
        )
        .unwrap_err();
        assert!(
            error.downcast_ref::<AttackRejected>().is_none(),
            "{error:#}"
        );
    }

    #[test]
    fn test_cawg_failed_output_preserves_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut args = cli_args(&[
            "-c",
            include_str!("../sample/cawg_metadata.json"),
            "-t",
            "cawg_author",
        ])
        .unwrap();
        args.settings = temp.path().join("settings.toml");
        args.output = Some(temp.path().join("output.jpg"));
        let existing =
            temp.path()
                .join(create_output_file_name(&args, "cawg_author".to_owned(), &0));
        fs::write(&existing, b"do not delete").unwrap();
        let mut index = 0;
        assert!(create_file(
            "cawg_author".to_owned(),
            &mut index,
            "name".to_owned(),
            &args,
            false
        )
        .is_err());
        assert_eq!(fs::read(existing).unwrap(), b"do not delete");
        assert_eq!(index, 0);
    }

    #[test]
    // Perform a unit test of injecting an XSS string in the title.
    // This will not create any files.
    fn test_xss_title() {
        let path: PathBuf = [r"sample", "image.jpg"].iter().collect();
        let manifest_temp: Result<PathBuf, ()> = Ok([r"sample", "test.json"].iter().collect());
        let manifest_file: Option<PathBuf> = manifest_temp.ok();
        let output_temp: Result<PathBuf, ()> =
            Ok([r"sample_out", "signed_image.jpg"].iter().collect());
        let output: Option<PathBuf> = output_temp.ok();
        let target = Target::Title;
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;
        let no_signing_verify: bool = false;
        let command: Option<Commands> = None;
        let parent: Option<PathBuf> = None;
        let field_type: String = String::from("title");
        let temp_dir = tempfile::tempdir().unwrap();
        let settings = temp_dir.path().join("settings.toml");

        let test_cli: CliArgs = CliArgs {
            path,
            manifest_file,
            output,
            target,
            attack_file,
            parent,
            config,
            detailed,
            force,
            verbose,
            command,
            no_signing_verify,
            settings,
        };

        let mut loop_index: i64 = 0;

        assert!(create_file(
            field_type,
            &mut loop_index,
            String::from("<script>alert('hi');</script>"),
            &test_cli,
            true
        )
        .is_ok())
    }

    #[test]
    // Perform a unit test of injecting an XSS string in regex mode.
    // This will not create any files.
    fn test_xss_regex_author() {
        let path: PathBuf = [r"sample", "image.jpg"].iter().collect();
        let manifest_temp: Result<PathBuf, ()> =
            Ok([r"sample", "author_name_regex.json"].iter().collect());
        let manifest_file: Option<PathBuf> = manifest_temp.ok();
        let output_temp: Result<PathBuf, ()> =
            Ok([r"sample_out", "signed_image.jpg"].iter().collect());
        let output: Option<PathBuf> = output_temp.ok();
        let target = Target::Regex;
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;
        let no_signing_verify: bool = false;
        let parent: Option<PathBuf> = None;
        let command: Option<Commands> = None;
        let field_type: String = String::from("regex");
        let temp_dir = tempfile::tempdir().unwrap();
        let settings = temp_dir.path().join("settings.toml");

        let test_cli: CliArgs = CliArgs {
            path,
            manifest_file,
            output,
            target,
            attack_file,
            parent,
            config,
            detailed,
            force,
            verbose,
            command,
            no_signing_verify,
            settings,
        };

        let mut loop_index: i64 = 0;

        assert!(create_file(
            field_type,
            &mut loop_index,
            String::from("<script>alert('hi');</script>"),
            &test_cli,
            true
        )
        .is_ok())
    }
}
