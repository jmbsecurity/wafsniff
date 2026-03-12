use clap::Parser;
use colored::*;
use regex::RegexBuilder;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "wafsniff", about = "⚡ Fast WAF detector — XSStrike + wafw00f combined", version)]
struct Cli {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value = "signatures.json")]
    signatures: String,

    #[arg(short, long, default_value = "10")]
    timeout: u64,

    #[arg(long, default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")]
    user_agent: String,

    #[arg(short, long)]
    verbose: bool,
}

struct Response {
    status: u16,
    headers_blob: String,
    body: String,
}

fn print_banner() {
    println!(
        "{}",
        r#"
               __           _ ________
 _      _____ / _|___ _ __ (_) __/ __/
| | /| / / _ | |_ / __| '_ \| | |_| |_
| |/ |/ / (_| |  _\__ | | | | |  _|  _|
|__/|__/\__,_|_| |___|_| |_|_|_| |_|

  ⚡ Fast WAF Detection Tool v2.0.0
"#
        .cyan()
    );
}

async fn do_request(client: &Client, url: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers_blob: String = {
        let h: String = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("'{}': '{}'", k.as_str(), v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{}}}", h)
    };
    let body = resp.text().await.unwrap_or_default();
    Ok(Response { status, headers_blob, body })
}

/// Send request with custom headers (used for no-UA probe)
async fn do_request_no_ua(
    timeout: u64,
    url: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(""));
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true)
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers_blob: String = {
        let h: String = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("'{}': '{}'", k.as_str(), v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{}}}", h)
    };
    let body = resp.text().await.unwrap_or_default();
    Ok(Response { status, headers_blob, body })
}

fn urlencode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

/// XSStrike-style signature matching against a response
fn match_signatures(
    sigs: &HashMap<String, Value>,
    resp: &Response,
    verbose: bool,
) -> Vec<(String, f64, Vec<String>)> {
    let mut results: Vec<(String, f64, Vec<String>)> = Vec::new();
    let code_str = resp.status.to_string();

    for (waf_name, sig) in sigs {
        let mut score: f64 = 0.0;
        let mut evidence: Vec<String> = Vec::new();

        // Page → +1
        let page_sign = sig.get("page").and_then(|v| v.as_str()).unwrap_or("");
        if !page_sign.is_empty() {
            if let Ok(re) = RegexBuilder::new(page_sign).case_insensitive(true).build() {
                if re.is_match(&resp.body) {
                    score += 1.0;
                    if let Some(m) = re.find(&resp.body) {
                        let s = &resp.body[m.start()..m.end()];
                        let d = if s.len() > 60 { &s[..60] } else { s };
                        evidence.push(format!("page: \"{}\"", d));
                    }
                }
            }
        }

        // Code → +0.5
        let code_sign = sig.get("code").and_then(|v| v.as_str()).unwrap_or("");
        if !code_sign.is_empty() {
            if let Ok(re) = RegexBuilder::new(code_sign).case_insensitive(true).build() {
                if re.is_match(&code_str) {
                    score += 0.5;
                    evidence.push(format!("code: {}", code_str));
                }
            }
        }

        // Headers → +1
        let headers_sign = sig.get("headers").and_then(|v| v.as_str()).unwrap_or("");
        if !headers_sign.is_empty() {
            if let Ok(re) = RegexBuilder::new(headers_sign).case_insensitive(true).build() {
                if re.is_match(&resp.headers_blob) {
                    score += 1.0;
                    if let Some(m) = re.find(&resp.headers_blob) {
                        let s = &resp.headers_blob[m.start()..m.end()];
                        evidence.push(format!("headers: \"{}\"", s));
                    }
                }
            }
        }

        // Cookies → +1
        let cookies_sign = sig.get("cookies").and_then(|v| v.as_str()).unwrap_or("");
        if !cookies_sign.is_empty() {
            if let Ok(re) = RegexBuilder::new(cookies_sign).case_insensitive(true).build() {
                if re.is_match(&resp.headers_blob) {
                    score += 1.0;
                    if let Some(m) = re.find(&resp.headers_blob) {
                        let s = &resp.headers_blob[m.start()..m.end()];
                        evidence.push(format!("cookie: \"{}\"", s));
                    }
                }
            }
        }

        if score > 0.0 {
            if verbose {
                println!(
                    "    {} {} (score: {:.1})",
                    "✓".green(),
                    waf_name,
                    score
                );
                for e in &evidence {
                    println!("      {} {}", "→".dimmed(), e);
                }
            }
            results.push((waf_name.clone(), score, evidence));
        }
    }

    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    results
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    print_banner();

    let sig_data = std::fs::read_to_string(&cli.signatures)
        .map_err(|e| format!("Cannot read '{}': {}", cli.signatures, e))?;
    let sigs: HashMap<String, Value> = serde_json::from_str(&sig_data)?;
    println!(
        "  {} Loaded {} signatures",
        "✓".green().bold(),
        sigs.len().to_string().bold()
    );
    println!(
        "  {} Target: {}",
        "→".cyan().bold(),
        cli.url.bold().underline()
    );
    println!();

    let client = Client::builder()
        .timeout(Duration::from_secs(cli.timeout))
        .danger_accept_invalid_certs(true)
        .user_agent(&cli.user_agent)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    // ═════════════════════════════════════════════════════════════════════
    // Phase 1: Normal request (wafw00f's resp1)
    // ═════════════════════════════════════════════════════════════════════
    println!("{}", "─── Phase 1: Normal Request ───".dimmed());

    let resp1 = match do_request(&client, &cli.url).await {
        Ok(r) => {
            println!(
                "  {} Status: {} | Body: {} bytes",
                "✓".green().bold(),
                r.status.to_string().bold(),
                r.body.len()
            );
            if cli.verbose {
                for chunk in r.headers_blob.as_bytes().chunks(120) {
                    println!("    {}", String::from_utf8_lossy(chunk).dimmed());
                }
            }
            r
        }
        Err(e) => {
            println!("  {} Failed: {}", "✗".red().bold(), e);
            return Ok(());
        }
    };

    // Passive fingerprinting on normal response
    let passive_matches = match_signatures(&sigs, &resp1, false);
    if !passive_matches.is_empty() {
        println!(
            "  {} Passive: {}",
            "⚡".yellow(),
            passive_matches
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
                .bold()
        );
    }

    // ═════════════════════════════════════════════════════════════════════
    // Phase 2: XSS attack request (wafw00f's resp2 / XSStrike's probe)
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "─── Phase 2: XSS Attack Probe ───".dimmed());

    let noise = "<script>alert(\"XSS\")</script>";
    let sep = if cli.url.contains('?') { "&" } else { "?" };
    let xss_url = format!("{}{}xss={}", cli.url, sep, urlencode(noise));

    if cli.verbose {
        println!("  {} {}", "URL".dimmed(), xss_url.dimmed());
    }

    let resp2 = match do_request(&client, &xss_url).await {
        Ok(r) => {
            println!(
                "  {} Status: {} | Body: {} bytes",
                if r.status >= 400 {
                    "!".red().bold()
                } else {
                    "✓".green().bold()
                },
                r.status.to_string().bold(),
                r.body.len()
            );
            if cli.verbose {
                for chunk in r.headers_blob.as_bytes().chunks(120) {
                    println!("    {}", String::from_utf8_lossy(chunk).dimmed());
                }
            }
            r
        }
        Err(e) => {
            println!("  {} Failed: {}", "✗".red().bold(), e);
            return Ok(());
        }
    };

    // ═════════════════════════════════════════════════════════════════════
    // Phase 3: No User-Agent request (wafw00f's resp3)
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "─── Phase 3: No User-Agent Probe ───".dimmed());

    let resp3 = match do_request_no_ua(cli.timeout, &cli.url).await {
        Ok(r) => {
            println!(
                "  {} Status: {} | Body: {} bytes",
                if r.status != resp1.status {
                    "!".yellow().bold()
                } else {
                    "✓".green().bold()
                },
                r.status.to_string().bold(),
                r.body.len()
            );
            Some(r)
        }
        Err(e) => {
            if cli.verbose {
                println!("  {} Failed: {}", "✗".red(), e);
            }
            None
        }
    };

    // ═════════════════════════════════════════════════════════════════════
    // Phase 4: SQLi attack request (wafw00f's centralAttack)
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "─── Phase 4: SQLi Attack Probe ───".dimmed());

    let sqli_noise = "' OR 1=1 --";
    let sqli_url = format!("{}{}id={}", cli.url, sep, urlencode(sqli_noise));

    if cli.verbose {
        println!("  {} {}", "URL".dimmed(), sqli_url.dimmed());
    }

    let resp4 = match do_request(&client, &sqli_url).await {
        Ok(r) => {
            println!(
                "  {} Status: {} | Body: {} bytes",
                if r.status >= 400 {
                    "!".red().bold()
                } else {
                    "✓".green().bold()
                },
                r.status.to_string().bold(),
                r.body.len()
            );
            Some(r)
        }
        Err(e) => {
            if cli.verbose {
                println!("  {} Failed: {}", "✗".red(), e);
            }
            None
        }
    };

    // ═════════════════════════════════════════════════════════════════════
    // Analysis — combine all results
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "─── Analysis ───".dimmed());

    // wafw00f behavioral detection
    let mut generic_reasons: Vec<String> = Vec::new();

    // Check: XSS probe got different status than normal
    if resp2.status != resp1.status {
        generic_reasons.push(format!(
            "XSS probe changed status: {} → {}",
            resp1.status, resp2.status
        ));
    }

    // Check: No-UA probe got different status
    if let Some(ref r3) = resp3 {
        if r3.status != resp1.status {
            generic_reasons.push(format!(
                "No User-Agent changed status: {} → {}",
                resp1.status, r3.status
            ));
        }
    }

    // Check: SQLi probe got different status
    if let Some(ref r4) = resp4 {
        if r4.status != resp1.status {
            generic_reasons.push(format!(
                "SQLi probe changed status: {} → {}",
                resp1.status, r4.status
            ));
        }
    }

    // Check: body size changed dramatically (custom error page)
    let base_len = resp1.body.len().max(1);
    let xss_len = resp2.body.len();
    let size_diff = ((xss_len as f64 - base_len as f64) / base_len as f64 * 100.0).abs();
    if size_diff > 50.0 && resp2.body.len() < resp1.body.len() {
        generic_reasons.push(format!(
            "XSS probe body size changed by {:.0}% (likely custom error page)",
            size_diff
        ));
    }

    if !generic_reasons.is_empty() {
        println!(
            "  {} Behavioral signals detected:",
            "⚠".yellow().bold()
        );
        for r in &generic_reasons {
            println!("    {} {}", "→".yellow(), r);
        }
    } else {
        println!("  {} No behavioral changes detected", "·".dimmed());
    }

    // Signature matching — check all attack responses
    // Pick the response most likely to contain WAF fingerprints (prefer blocked ones)
    let mut all_matches: HashMap<String, (f64, Vec<String>)> = HashMap::new();

    // Always check XSS response
    let xss_matches = match_signatures(&sigs, &resp2, cli.verbose);
    for (name, score, evidence) in &xss_matches {
        let entry = all_matches.entry(name.clone()).or_insert((0.0, Vec::new()));
        if *score > entry.0 {
            entry.0 = *score;
        }
        for e in evidence {
            if !entry.1.contains(e) {
                entry.1.push(e.clone());
            }
        }
    }

    // Check SQLi response too
    if let Some(ref r4) = resp4 {
        let sqli_matches = match_signatures(&sigs, r4, false);
        for (name, score, evidence) in &sqli_matches {
            let entry = all_matches.entry(name.clone()).or_insert((0.0, Vec::new()));
            if *score > entry.0 {
                entry.0 = *score;
            }
            for e in evidence {
                if !entry.1.contains(e) {
                    entry.1.push(e.clone());
                }
            }
        }
    }

    // Also check normal response for passive fingerprints
    for (name, score, evidence) in &passive_matches {
        let entry = all_matches.entry(name.clone()).or_insert((0.0, Vec::new()));
        if *score > entry.0 {
            entry.0 = *score;
        }
        for e in evidence {
            if !entry.1.contains(e) {
                entry.1.push(e.clone());
            }
        }
    }

    // Sort all by score
    let mut final_results: Vec<(String, f64, Vec<String>)> = all_matches
        .into_iter()
        .map(|(name, (score, evidence))| (name, score, evidence))
        .collect();
    final_results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    // ═════════════════════════════════════════════════════════════════════
    // Results
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "═══════════════════════════════════════".bold());
    println!("{}", "              RESULT                   ".bold());
    println!("{}", "═══════════════════════════════════════".bold());

    if !final_results.is_empty() {
        let (ref top_name, top_score, ref top_evidence) = final_results[0];
        println!();
        println!(
            "  {} WAF detected: {}",
            "🛡 ".bold(),
            top_name.bold().red()
        );
        println!(
            "  {} Score: {:.1}/3.5",
            "→".cyan(),
            top_score
        );
        println!("  {} Evidence:", "→".cyan());
        for e in top_evidence {
            println!("    {} {}", "→".green(), e);
        }

        // Show behavioral reasons if any
        if !generic_reasons.is_empty() {
            println!("  {} Behavioral:", "→".cyan());
            for r in &generic_reasons {
                println!("    {} {}", "→".yellow(), r);
            }
        }

        // Show runners up
        if final_results.len() > 1 {
            println!();
            println!("  {} Also matched:", "·".dimmed());
            for (name, score, _) in &final_results[1..] {
                println!(
                    "    {} {} ({:.1})",
                    "·".dimmed(),
                    name.dimmed(),
                    score
                );
            }
        }
    } else if !generic_reasons.is_empty() {
        // No signature match but behavioral detection fired
        println!();
        println!(
            "  {} {}",
            "⚠".yellow().bold(),
            "Generic WAF detected (behavioral)".bold().yellow()
        );
        println!("  {} The server responded differently to attack payloads:", "→".cyan());
        for r in &generic_reasons {
            println!("    {} {}", "→".yellow(), r);
        }
        println!(
            "  {}",
            "  A WAF or security solution is likely active but not in our signature database.".dimmed()
        );
    } else {
        println!();
        println!(
            "  {} {}",
            "✓".green().bold(),
            "WAF Status: Offline".bold().green()
        );
        println!(
            "  {}",
            "  No WAF signatures matched and no behavioral changes detected.".dimmed()
        );
    }

    println!();
    Ok(())
}
