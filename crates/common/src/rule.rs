//! Routing rule engine: match a request host against an ordered rule list
//! and yield a [`Policy`] (proxy / direct / block).
//!
//! Rule strings follow the `type:value,policy` shape, e.g.
//!
//! ```text
//! domain-suffix:google.com,proxy
//! domain-keyword:github,direct
//! ip-cidr:10.0.0.0/8,direct
//! domain:ads.example.com,block
//! ```

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::addr::Host;

/// What to do with a matched request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    /// Forward through the remote openppp3 server.
    Proxy,
    /// Connect directly, bypassing the remote server.
    Direct,
    /// Refuse the request.
    Block,
}

impl Policy {
    /// Parses the policy keyword used in rule strings.
    ///
    /// # Errors
    ///
    /// Unknown keyword.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "proxy" => Ok(Self::Proxy),
            "direct" => Ok(Self::Direct),
            "block" => Ok(Self::Block),
            _ => Err(format!("unknown policy: {s:?} (expected proxy|direct|block)")),
        }
    }
}

#[derive(Debug, Clone)]
enum Rule {
    /// Exact (case-insensitive) domain match.
    Domain(String, Policy),
    /// Domain suffix match: the pattern itself or any subdomain.
    DomainSuffix(String, Policy),
    /// Substring match on the domain.
    DomainKeyword(String, Policy),
    /// CIDR match on a literal IP target.
    IpCidr(IpNet, Policy),
}

/// An ordered rule list with a fallback policy (first match wins).
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
    final_policy: Policy,
}

impl RuleSet {
    /// Builds a ruleset from `type:value,policy` strings.
    ///
    /// # Errors
    ///
    /// The first malformed rule string, with its index.
    pub fn parse(specs: &[String], final_policy: Policy) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let spec = spec.trim();
            let (body, policy) = spec
                .rsplit_once(',')
                .ok_or_else(|| format!("rule #{i} {spec:?}: missing \",policy\" suffix"))?;
            let policy = Policy::parse(policy.trim())
                .map_err(|e| format!("rule #{i} {spec:?}: {e}"))?;

            let rule = if let Some(domain) = body.strip_prefix("domain-suffix:") {
                Rule::DomainSuffix(normalize_domain(domain)?, policy)
            } else if let Some(domain) = body.strip_prefix("domain-keyword:") {
                let kw = normalize_domain(domain)?;
                if kw.is_empty() {
                    return Err(format!("rule #{i} {spec:?}: empty keyword"));
                }
                Rule::DomainKeyword(kw, policy)
            } else if let Some(domain) = body.strip_prefix("domain:") {
                Rule::Domain(normalize_domain(domain)?, policy)
            } else if let Some(cidr) = body.strip_prefix("ip-cidr:") {
                let net: IpNet = cidr
                    .trim()
                    .parse()
                    .map_err(|e| format!("rule #{i} {spec:?}: invalid cidr: {e}"))?;
                Rule::IpCidr(net, policy)
            } else {
                return Err(format!(
                    "rule #{i} {spec:?}: unknown rule type (expected domain|domain-suffix|domain-keyword|ip-cidr)"
                ));
            };
            rules.push(rule);
        }
        Ok(Self { rules, final_policy })
    }

    /// The fallback policy applied when no rule matches.
    #[must_use]
    pub fn final_policy(&self) -> Policy {
        self.final_policy
    }

    /// Resolves the policy for a request host. Domain rules are skipped for
    /// literal-IP targets and CIDR rules for domain targets (no local DNS
    /// resolution by design: what the client cannot see, the censor cannot
    /// see either).
    #[must_use]
    pub fn decide(&self, host: &Host) -> Policy {
        match host {
            Host::Domain(domain) => {
                let d = request_domain(domain);
                for rule in &self.rules {
                    match rule {
                        Rule::Domain(pattern, p) => {
                            if &d == pattern {
                                return *p;
                            }
                        }
                        Rule::DomainSuffix(pattern, p) => {
                            if &d == pattern
                                || (d.len() > pattern.len()
                                    && d.ends_with(pattern.as_str())
                                    && d.as_bytes()[d.len() - pattern.len() - 1] == b'.')
                            {
                                return *p;
                            }
                        }
                        Rule::DomainKeyword(kw, p) => {
                            if d.contains(kw.as_str()) {
                                return *p;
                            }
                        }
                        Rule::IpCidr(_, _) => {}
                    }
                }
            }
            Host::Ip(ip) => {
                for rule in &self.rules {
                    if let Rule::IpCidr(net, p) = rule {
                        if net.contains(ip) {
                            return *p;
                        }
                    }
                }
            }
        }
        self.final_policy
    }
}

/// Lowercases and strips the trailing dot of a domain pattern.
fn normalize_domain(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err(String::from("empty domain"));
    }
    if !s.bytes().all(|b| b == b'.' || b == b'-' || b.is_ascii_alphanumeric()) {
        return Err(format!("invalid domain characters: {s:?}"));
    }
    Ok(s)
}

/// Normalizes a request domain for matching (must not fail for any name the
/// inbound protocols accepted; falls back to plain lowercase).
fn request_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn ruleset(specs: &[&str], final_policy: Policy) -> RuleSet {
        let owned: Vec<String> = specs.iter().map(ToString::to_string).collect();
        RuleSet::parse(&owned, final_policy).unwrap()
    }

    fn domain(s: &str) -> Host {
        Host::Domain(String::from(s))
    }

    #[test]
    fn suffix_matches_self_and_subdomains_only() {
        let rs = ruleset(&["domain-suffix:google.com,proxy"], Policy::Direct);
        assert_eq!(rs.decide(&domain("google.com")), Policy::Proxy);
        assert_eq!(rs.decide(&domain("WWW.Google.COM")), Policy::Proxy);
        assert_eq!(rs.decide(&domain("mail.google.com.")), Policy::Proxy);
        assert_eq!(rs.decide(&domain("notgoogle.com")), Policy::Direct);
        assert_eq!(rs.decide(&domain("google.com.evil.io")), Policy::Direct);
    }

    #[test]
    fn exact_and_keyword_rules() {
        let rs = ruleset(&["domain:a.io,block", "domain-keyword:ads,direct"], Policy::Proxy);
        assert_eq!(rs.decide(&domain("a.io")), Policy::Block);
        assert_eq!(rs.decide(&domain("sub.a.io")), Policy::Proxy); // exact != suffix
        assert_eq!(rs.decide(&domain("ads.example.com")), Policy::Direct);
        assert_eq!(rs.decide(&domain("xADSx.com")), Policy::Direct); // keyword is substring
    }

    #[test]
    fn cidr_rules_match_ips_only() {
        let rs = ruleset(
            &["ip-cidr:10.0.0.0/8,direct", "ip-cidr:fe80::/10,block"],
            Policy::Proxy,
        );
        assert_eq!(
            rs.decide(&Host::Ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))),
            Policy::Direct
        );
        assert_eq!(
            rs.decide(&Host::Ip(IpAddr::V6("fe80::1".parse().unwrap()))),
            Policy::Block
        );
        // Domain requests skip CIDR rules entirely.
        assert_eq!(rs.decide(&domain("10.0.0.1.com")), Policy::Proxy);
    }

    #[test]
    fn first_match_wins_and_final_applies() {
        let rs = ruleset(&["domain-suffix:cn,direct", "domain:x.cn,block"], Policy::Proxy);
        assert_eq!(rs.decide(&domain("x.cn")), Policy::Direct);
        assert_eq!(rs.decide(&domain("unmatched.org")), Policy::Proxy);
    }

    #[test]
    fn parse_errors_are_actionable() {
        let owned = vec![String::from("domain-suffix:google.com")];
        assert!(RuleSet::parse(&owned, Policy::Proxy).unwrap_err().contains("#0"));

        let owned = vec![String::from("domain-suffix:google.com,teleport")];
        assert!(RuleSet::parse(&owned, Policy::Proxy)
            .unwrap_err()
            .contains("unknown policy"));

        let owned = vec![String::from("geoip:cn,direct")];
        assert!(RuleSet::parse(&owned, Policy::Proxy)
            .unwrap_err()
            .contains("unknown rule type"));

        let owned = vec![String::from("ip-cidr:10.0.0.0/33,direct")];
        assert!(RuleSet::parse(&owned, Policy::Proxy)
            .unwrap_err()
            .contains("invalid cidr"));
    }
}
