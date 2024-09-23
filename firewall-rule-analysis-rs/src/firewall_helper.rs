use core::slice;

use windows::{
    core::ComInterface,
    Win32::{
        Foundation::*,
        NetworkManagement::WindowsFirewall::*,
        System::{
            Com::*,
            Ole::*,
            Variant::{self, VariantChangeType, VARIANT, VT_ARRAY, VT_BSTR, VT_DISPATCH, VT_EMPTY, VT_VARIANT},
        },
    },
};

#[derive(Debug)]
pub struct NormalizedFirewallRule {
    rule_name: String,
    rule_description: String,
    normalized_rule_details: String,
    rule_direction: NET_FW_RULE_DIRECTION,
    rule_enabled: bool,
}

impl PartialEq for NormalizedFirewallRule {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_rule_details == other.normalized_rule_details
    }
}

impl Eq for NormalizedFirewallRule {}

impl PartialOrd for NormalizedFirewallRule {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.normalized_rule_details.partial_cmp(&other.normalized_rule_details)
    }
}

impl Ord for NormalizedFirewallRule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.normalized_rule_details.cmp(&other.normalized_rule_details)
    }
}

unsafe fn normalize_interfaces(interfaces: VARIANT) -> windows::core::Result<String> {
    let mut result = "".to_string();
    let vt = interfaces.Anonymous.Anonymous.vt;
    if vt == VT_EMPTY {
        // it's acceptable to be either EMPTY
        // or an ARRAY of VARIANTs
        return Ok(result);
    }
    if vt.0 != VT_ARRAY.0 | VT_VARIANT.0 {
        return Err(windows::core::Error::new(
            E_UNEXPECTED,
            "Interfaces is not an array of variants".into(),
        ));
    }
    let parray = interfaces.Anonymous.Anonymous.Anonymous.parray.as_ref().ok_or(
        windows::core::Error::new(E_FAIL, "Interfaces is not an array".into()),
    )?;
    let array_dimensions = SafeArrayGetDim(parray);
    for i in 0..array_dimensions {
        let l_bound = SafeArrayGetLBound(parray, i + 1)?;
        let u_bound =  SafeArrayGetUBound(parray, i + 1)?;
        for j in l_bound..=u_bound {
            let mut element = VARIANT::default();
            SafeArrayGetElement(parray, core::ptr::addr_of!( j), core::mem::transmute(core::ptr::addr_of_mut!(element)))?;
            if element.Anonymous.Anonymous.vt != VT_BSTR{
                return Err(windows::core::Error::new(
                    E_UNEXPECTED,
                    "Element is not a BSTR".into(),
                ));
            }
            result += element.Anonymous.Anonymous.Anonymous.bstrVal.to_string().as_str(); 
        }
    }
    return Ok(result);

}

unsafe fn normalize_firewall_rule(
    rule: INetFwRule,
) -> windows::core::Result<NormalizedFirewallRule> {
    let rule_name = rule.Name()?.to_string();
    let rule_description = rule.Description()?.to_string();
    let rule_direction = rule.Direction()?;
    let rule_enabled = rule.Enabled()?.into();
    let mut normalized_rule_details = "".to_string();
    normalized_rule_details += format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        rule.ApplicationName()?,
        rule.ServiceName()?,
        rule.Protocol()?,
        rule.LocalPorts()?,
        rule.RemotePorts()?,
        rule.LocalAddresses()?,
        rule.RemoteAddresses()?,
        rule.IcmpTypesAndCodes()?,
        // enum: rule.Direction()?,
        // special: stringify!(rule.Interfaces()?),
        rule.InterfaceTypes()?,
        rule.Grouping()?,
        rule.Profiles()?,
        // enum: rule.EdgeTraversal()?,
        // enum: rule.Action()?
    )
    .as_str();

    normalized_rule_details += normalize_interfaces(rule.Interfaces()?)?.as_str();

    normalized_rule_details += format!(
        "{:?}{:?}{:?}",
        rule.Direction()?,
        rule.EdgeTraversal()?,
        rule.Action()?
    )
    .as_str();

    match rule.cast::<INetFwRule2>() {
        Ok(rule2) => {
            normalized_rule_details += format!("{}", rule2.EdgeTraversalOptions()?).as_str();
        }
        Err(_) => {}
    }

    match rule.cast::<INetFwRule3>() {
        Ok(rule3) => {
            normalized_rule_details += format!(
                "{}{}{}{}{}{}",
                rule3.LocalAppPackageId()?,
                rule3.LocalUserOwner()?,
                rule3.LocalUserAuthorizedList()?,
                rule3.RemoteUserAuthorizedList()?,
                rule3.RemoteMachineAuthorizedList()?,
                rule3.SecureFlags()?
            )
            .as_str();
        }
        Err(_) => {}
    }

    normalized_rule_details = normalized_rule_details.to_lowercase();

    return Ok(NormalizedFirewallRule {
        rule_name,
        rule_description,
        normalized_rule_details,
        rule_direction,
        rule_enabled,
    });
}

pub fn build_firewall_rules() -> windows::core::Result<Vec<NormalizedFirewallRule>> {
    let mut return_info = Vec::new();

    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)?;
        {
            let policy: INetFwPolicy2 =
                CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
            let rules = match policy.Rules() {
                Ok(rules) => rules,
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            };
            let enumerator = rules._NewEnum()?;
            let enumv = enumerator.cast::<IEnumVARIANT>()?;
            let mut hr = S_OK;
            let mut var: VARIANT = VARIANT::default();
            while hr.is_ok() && hr != S_FALSE {
                let mut fetched: u32 = 1;
                hr = enumv.Next(slice::from_mut(&mut var), core::ptr::addr_of_mut!(fetched));
                if hr.is_ok() && hr != S_FALSE && fetched > 0 {
                    VariantChangeType(&mut var, &var, Variant::VAR_CHANGE_FLAGS(0), VT_DISPATCH)?;
                    let idispatch = var.Anonymous.Anonymous.Anonymous.pdispVal.as_ref().ok_or(
                        windows::core::Error::new(E_FAIL, "IDispatch failed to convert".into()),
                    )?;
                    let rule = idispatch.cast::<INetFwRule>()?;
                    return_info.push(normalize_firewall_rule(rule)?);
                }
            }
        }
        CoUninitialize();
    }
    return Ok(return_info);
}
