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
    collections::HashMap,
    fs::{create_dir_all, remove_file, File},
    io::{self, BufRead},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
// These are not used in the current implementation: ManifestDefinition, Manifest, and ManifestStore
#[allow(deprecated)]
use c2pa::{
    assertions::{
        labels::{self, CREATIVE_WORK},
        CreativeWork, SchemaDotOrgPerson,
    },
    Builder, ClaimGeneratorInfo, Error, Ingredient, Reader,
};
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::debug;
use regex::Regex;
use serde_json::{Map, Value};

mod signer;
// This is not used in the current implementation
/* use serde::Deserialize; */
use std::fs;

use signer::SignConfig;
use url::Url;

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
    arg_required_else_help = true
)]
struct CliArgs {
    /// The path for the original asset image
    #[arg(required = true)]
    path: PathBuf,

    /// Path to manifest definition JSON file
    #[arg(short = 'm', required = true)]
    manifest_file: Option<PathBuf>,

    /// Path to the output folder and base file name for the output
    #[arg(short = 'o', required = true)]
    output: Option<PathBuf>,

    /// The target field to replace or indicating the use of regex mode
    #[arg(
        short = 't',
        required = true,
        value_parser = clap::builder::PossibleValuesParser::new([
        "author",
        "title",
        "format",
        "label",
        "vendor",
        "person_identifier",
        "instance_id",
        "claim_generator",
        "regex"])
    )]
    target: Option<String>,

    /// The file containing the attack strings to use
    #[arg(short = 'a', required = true)]
    attack_file: String,

    /// Path to a parent file
    #[arg(short = 'p')]
    parent: Option<PathBuf>,

    /// Manifest definition passed as a JSON string
    #[arg(short = 'c')]
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

// loads an ingredient, allowing for a folder or json ingredient
fn load_ingredient(path: &Path) -> Result<Ingredient> {
    // if the path is a folder, look for ingredient.json
    let mut path_buf = PathBuf::from(path);
    let path = if path.is_dir() {
        path_buf = path_buf.join("ingredient.json");
        path_buf.as_path()
    } else {
        path
    };
    if path.extension() == Some(std::ffi::OsStr::new("json")) {
        let json = std::fs::read_to_string(path)?;
        let mut ingredient: Ingredient = serde_json::from_slice(json.as_bytes())?;
        if let Some(base) = path.parent() {
            ingredient.resources_mut().set_base_path(base);
        }
        Ok(ingredient)
    } else {
        Ok(Ingredient::from_file(path)?)
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

// This function will handle any specific trust settings that are provided via the command line.
fn configure_sdk(args: &CliArgs) -> Result<()> {
    const TA: &str = r#"{"trust": { "trust_anchors": replacement_val } }"#;
    const AL: &str = r#"{"trust": { "allowed_list": replacement_val } }"#;
    const TC: &str = r#"{"trust": { "trust_config": replacement_val } }"#;
    const VS: &str = r#"{"verify": { "verify_after_sign": replacement_val } }"#;

    let mut enable_trust_checks = false;

    if let Some(Commands::Trust {
        trust_anchors,
        allowed_list,
        trust_config,
    }) = &args.command
    {
        if let Some(trust_list) = &trust_anchors {
            let data = load_trust_resource(trust_list)?;
            debug!("Using trust anchors from {trust_list:?}");
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = TA.replace("replacement_val", &replacement_val);

            #[allow(deprecated)]
            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = &allowed_list {
            let data = load_trust_resource(allowed_list)?;
            debug!("Using allowed list from {allowed_list:?}");
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = AL.replace("replacement_val", &replacement_val);

            #[allow(deprecated)]
            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = &trust_config {
            let data = load_trust_resource(trust_config)?;
            debug!("Using trust config from {trust_config:?}");
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = TC.replace("replacement_val", &replacement_val);

            #[allow(deprecated)]
            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }
    }

    // if any trust setting is provided enable the trust checks
    if enable_trust_checks {
        #[allow(deprecated)]
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
    } else {
        #[allow(deprecated)]
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": false} }"#, "json")?;
    }

    // enable or disable verification after signing
    {
        let replacement_val = serde_json::Value::Bool(!args.no_signing_verify).to_string();
        let setting = VS.replace("replacement_val", &replacement_val);

        #[allow(deprecated)]
        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    Ok(())
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

// Malicious strings may have double quotes or backslashes that need to be escaped for the JSON manifest. This function will take the injection string and escape any backslashes or double quotes that might be mistakenly interpreted by JSON.
//
// A trailing backslash needs to be escaped because it may be the last character in the string causing the double quote terminating the string to be escaped. Double quotes need to be escaped because they will conflict with existing JSON double quotes.
//
// This returns the injection string with the appropriate characters escaped.
fn escape_malicious_string(mal_string: String) -> Result<String> {
    // First escape any ending backslashes
    // Only escape if the last backslash isn't already escaped.
    let escaped_string: String = if mal_string.ends_with('\\') && !mal_string.ends_with("\\\\") {
        let escape_backslash = Regex::new(r"(?P<a>\\)").unwrap();
        let temp = escape_backslash
            .replace_all(mal_string.as_str(), "\\\\")
            .to_string();

        // Next, add backslashes for any existing double quotes
        let escape_d_quote = Regex::new(r#"(?P<a>")"#).unwrap();
        escape_d_quote
            .replace_all(temp.as_str(), r#"\""#)
            .to_string()
    } else {
        // Add backslashes for any existing double quotes
        let escape_d_quote = Regex::new(r#"(?P<a>")"#).unwrap();
        escape_d_quote
            .replace_all(mal_string.as_str(), r#"\""#)
            .to_string()
    };
    Ok(escaped_string)
}

// Remove any pre-existing assertion of the same type as the malicious assertion.
fn remove_existing_assertion(
    orig_json: String,
    field_type: String,
    verbose: bool,
) -> HashMap<String, Value> {
    let map: Map<String, Value> = serde_json::from_str(&orig_json).expect("failed to read file");

    let blank_json: &str = "{}";
    let mut new_json: HashMap<String, Value> =
        serde_json::from_str(blank_json).expect("Couldn't create blank map");

    for entry in map.keys() {
        if entry == "assertions" {
            let mut vec = Vec::new();
            for assertion in map[entry].as_array().unwrap() {
                if assertion["label"].eq(labels::CREATIVE_WORK) {
                    let data = assertion["data"].as_object().unwrap();

                    // Only push the value if it doesn't contain authorship information
                    if !(data.contains_key("author") && field_type.eq("author")
                        || (data.contains_key("author") && field_type.eq("person_identifier"))
                        || (data.contains_key("creator") && field_type.eq("person_identifier")))
                    {
                        vec.push(assertion.clone());
                    } else if verbose {
                        println!("Dropping Creative Work from original source");
                    }
                } else {
                    vec.push(assertion.clone());
                }
            }
            new_json.insert("assertions".to_string(), Value::Array(vec));
        } else {
            new_json.insert(entry.to_string(), map[entry].clone());
        }
    }

    new_json
}

// For attack types of author or person_identifier, we will create a new malicious
// Creative Work assertion with the appropriate malicous fields.
#[allow(deprecated)]
fn malicious_creative_work(
    field_type: String,
    mal_string: &String,
) -> Result<Option<CreativeWork>> {
    #[allow(deprecated)]
    let mut new_creative_work: Option<CreativeWork> = None;

    if field_type.eq("author") {
        #[allow(deprecated)]
        let author = SchemaDotOrgPerson::new().set_name(mal_string.to_owned())?;
        new_creative_work = Some(CreativeWork::new().add_author(author).expect("add_author"));
    } else if field_type.eq("person_identifier") {
        #[allow(deprecated)]
        let cw_person = SchemaDotOrgPerson::new()
            .set_name("Malicious User".to_owned())
            .unwrap()
            .set_identifier(mal_string.to_owned())
            .unwrap()
            .insert("@id".to_owned(), [mal_string.to_owned()].to_vec())
            .unwrap();
        new_creative_work = Some(
            CreativeWork::new()
                .add_author(cw_person.clone())
                .expect("add_author")
                // example of adding a different kind of person field
                .insert("creator".to_owned(), cw_person)
                .expect("insert"),
        );
    }

    Ok(new_creative_work)
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
    #[allow(deprecated)]
    let mut new_creative_work: Option<CreativeWork> = None;

    if field_type.eq("author") || field_type.eq("person_identifier") {
        new_creative_work = malicious_creative_work(field_type.clone(), mal_string).unwrap();
    }

    if let Some(new_assertion) = new_creative_work {
        builder.add_assertion_json(CREATIVE_WORK, &new_assertion)?;
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

        builder
            .sign_file(signer.as_ref(), args.path.clone(), output.clone())
            .context("signing file")?;

        // generate a report on the output file
        let reader = Reader::from_file(&output).map_err(special_errs)?;
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
    let re: Regex = Regex::new(r"(?P<a>C2PA_ATTACK)").unwrap();

    if re.is_match(json.as_str()) && field_type.eq("regex") {
        let escaped_string: String = escape_malicious_string(mal_string).unwrap();

        let after = re.replace_all(json.as_str(), escaped_string);

        Ok(after.to_string())
    } else {
        let new_map = remove_existing_assertion(json, field_type, verbose);
        let new_string: String = serde_json::to_string(&new_map).unwrap();
        Ok(new_string)
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

    let is_fragment = matches!(
        &args.command,
        Some(Commands::Fragment { fragments_glob: _ })
    );

    // configure the SDK
    configure_sdk(args).context("Could not configure c2pa-rs")?;

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
                std::env::current_dir().ok(),
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
        let mut builder = Builder::from_json(&new_json)?;

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

        // If we successfully have a manifest config, then proceed with creating attack files.
        if let Some(parent_path) = &args.parent {
            let mut ingredient = load_ingredient(parent_path)?;
            ingredient.set_is_parent();
            builder.add_ingredient(ingredient);
        }

        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        let has_parent = builder.definition.ingredients.iter().any(|i| i.is_parent());
        if !has_parent && !is_fragment {
            let mut source_ingredient = Ingredient::from_file(&args.path)?;
            if source_ingredient.manifest_data().is_some() {
                source_ingredient.set_is_parent();
                builder.add_ingredient(source_ingredient);
            }
        }

        let result = output_file(
            args,
            &mut builder,
            &sign_config,
            field_type.clone(),
            &escaped_string,
            loop_index,
            testing_mode,
        );
        match result {
            Ok(_v) => {
                *loop_index += 1;
            }
            Err(e) => {
                println!("Failed to process file: {e:?}");
                let new_filename = create_output_file_name(args, field_type.clone(), loop_index);
                println!("Removing file: {new_filename}");
                if let Some(mut output) = args.output.clone() {
                    output.pop();
                    output.push(new_filename);
                    fs::remove_file(output)?;
                }
                *loop_index += 1;
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();

    // Verify command line flag for the target is one that is supported by this tool
    let field_type: String = if let Some(target) = args.target.clone() {
        let target_str = target.to_owned();
        if target_str.ne("author")
            && target_str.ne("title")
            && target_str.ne("claim_generator")
            && target_str.ne("regex")
            && target_str.ne("person_identifier")
            && target_str.ne("instance_id")
            && target_str.ne("label")
            && target_str.ne("format")
            && target_str.ne("vendor")
        {
            bail!(
                "Unrecognized field type. Allowed values: author, title, label, format, vendor, \
                instance_id, claim_generator, person_identifier, or regex"
            );
        }
        target
    } else {
        bail!("Field type not provided. Please add the '-t' flag.");
    };

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
        for mal_string in lines.map_while(Result::ok) {
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
                    println!("Failed to create file: {loop_index}");
                    println!("Failed due to error: {e:?}");
                    loop_index += 1;
                }
            }
        }
    } else {
        bail!("ERROR: Could not find the attack injection file!");
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::PathBuf;

    use super::*;
    use crate::CliArgs;

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
        let target_temp: Result<String, ()> = Ok(String::from("title"));
        let target: Option<String> = target_temp.ok();
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;
        let no_signing_verify: bool = false;
        let command: Option<Commands> = None;
        let parent: Option<PathBuf> = None;
        let field_type: String = String::from("title");

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
        let target_temp: Result<String, ()> = Ok(String::from("regex"));
        let target: Option<String> = target_temp.ok();
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;
        let no_signing_verify: bool = false;
        let parent: Option<PathBuf> = None;
        let command: Option<Commands> = None;
        let field_type: String = String::from("regex");

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
