mod firewall_helper;

fn main() -> windows::core::Result<()> {
    let mut rules = firewall_helper::build_firewall_rules()?;
    rules.sort_unstable();
    println!("Rules: {}", rules.len());

    let mut last_rule: firewall_helper::NormalizedFirewallRule = Default::default();
    let mut duplicate_rule_count = 0;
    for rule in rules {
        if last_rule == rule {
            println!("Duplicate rule: {:?} {:?}", last_rule, rule);
            duplicate_rule_count += 1;
        } else {
            last_rule = rule;
        }
    }

    println!("Duplicate rules: {}", duplicate_rule_count);

    return Ok(());
}
