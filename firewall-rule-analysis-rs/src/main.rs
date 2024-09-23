

mod firewall_helper;

fn main() -> windows::core::Result<()> {

    let mut rules = firewall_helper::build_firewall_rules()?;
    rules.sort_unstable();
    println!("Rules: {}", rules.len());

    let mut last_rule: Option<firewall_helper::NormalizedFirewallRule> = None;
    let mut duplicate_rule_count = 0;
    for rule in rules {
        match last_rule {
            Some(last_rule) => {
                if last_rule == rule {
                    println!("Duplicate rule: {:?} {:?}", last_rule, rule);
                    duplicate_rule_count += 1;
                }
            }
            None => {}
        }
        last_rule = Some(rule);
    }
    
    println!("Duplicate rules: {}", duplicate_rule_count);
    
    return Ok(());
}
