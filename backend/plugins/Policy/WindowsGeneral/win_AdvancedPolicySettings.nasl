###############################################################################
# OpenVAS Vulnerability Test
# $Id: win_AdvancedPolicySettings.nasl 10563 2018-07-22 10:40:42Z cfischer $
#
# Read all Windows Advanced Policy Security Settings (Windows)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.312525");
  script_version("$Revision: 10563 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-22 12:40:42 +0200 (Sun, 22 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 12:03:14 +0200 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read all Windows Policy Security Settings (Windows)");
  script_family("Policy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary",value:"Read all Windows Advanced Policy Security Settings (Windows)");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

if(get_kb_item("SMB/WindowsVersion") < "6.1"){
  policy_logging(text:'Host is not at least a Microsoft Windows 7 system.
Older versions of Windows are not supported any more. Please update the
Operating System.');
  exit(0);
}

function auditing (pol){
  ret = "";
  if( "no auditing" >< tolower(pol) ){
    return("No Auditing");
  }
  if( "success" >< tolower(pol) ){
    ret = "Success";
  }
  if( "failure" >< tolower(pol) ){
    if( ret == "Success"){
      ret += " and ";
    }
    ret += "Failure";
  }

  return ret;
}

usrname = kb_smb_login();
domain  = kb_smb_domain();

if (domain){
  usrname = domain + '/' + usrname;
}
passwd = kb_smb_password();

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  policy_logging(text:'Error: Usage of win_cmd_exec required for this check was disabled manually within "Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)".');
  exit(0);
}

AdvancedPolicy = win_cmd_exec(cmd:"auditpol /get /category:*", password:passwd, username:usrname);
if(!AdvancedPolicy || "smb sessionerror" >< tolower(AdvancedPolicy)){
  policy_logging(text:'Error: Could not query the audit policy.');
  exit(0);
}
log = 'Advanced Audit Policy is configured to log following:\n\n' + AdvancedPolicy;

AdvancedPolicy = split(AdvancedPolicy, keep:FALSE);
foreach pol (AdvancedPolicy) {
  if ("security system extension" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Security System Extension';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/System/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SystemSecurityExtension", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemSecurityExtension/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemSecurityExtension/FIX", value:fixtext);
  }
  if ("system integrity" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit System Integrity';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/System/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SystemIntegrity", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemIntegrity/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemIntegrity/FIX", value:fixtext);
  }
  if ("ipsec driver" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit IPsec Driver';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/System/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecDriver", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecDriver/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecDriver/FIX", value:fixtext);
  }
  if ("other system events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other System Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/System/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherSystemEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherSystemEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherSystemEvents/FIX", value:fixtext);
  }
  if ("security state change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Security State Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/System/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityStateChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityStateChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityStateChange/FIX", value:fixtext);
  }
  if ("  logon " >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Logon';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/Logon", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/Logon/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/Logon/FIX", value:fixtext);
  }
  if ("  logoff " >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Logoff';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/Logoff", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/Logoff/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/Logoff/FIX", value:fixtext);
  }
  if ("account lockout" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Account Lockout';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/AccountLockout", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/AccountLockout/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/AccountLockout/FIX", value:fixtext);
  }
  if ("ipsec main mode" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit IPsec Main Mode';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecMainMode", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecMainMode/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecMainMode/FIX", value:fixtext);
  }
  if ("ipsec quick mode" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit IPsec Quick Mode';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecQuickMode", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecQuickMode/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecQuickMode/FIX", value:fixtext);
  }
  if ("ipsec extended mode" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit IPsec Extended Mode';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecExtendedMode", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecExtendedMode/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecExtendedMode/FIX", value:fixtext);
  }
  if ("special logon" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Special Logon';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SpecialLogon", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SpecialLogon/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SpecialLogon/FIX", value:fixtext);
  }
  if ("other logon/logoff events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Logon/Logoff Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherLogonLogoffEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherLogonLogoffEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherLogonLogoffEvents/FIX", value:fixtext);
  }
  if ("network policy server" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Network Policy Server';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/NetworkPolicyServer", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/NetworkPolicyServer/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/NetworkPolicyServer/FIX", value:fixtext);
  }
  if ("user / device claims" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit User / Device Claims';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/UserDeviceClaims", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/UserDeviceClaims/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/UserDeviceClaims/FIX", value:fixtext);
  }
  if ("group membership" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Group Membership';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Logon/Logoff/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/GroupMembership", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/GroupMembership/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/GroupMembership/FIX", value:fixtext);
  }
  if ("file system" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit File System';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/FileSystem", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/FileSystem/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/FileSystem/FIX", value:fixtext);
  }
  if ("registry" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Registry';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/Registry", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/Registry/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/Registry/FIX", value:fixtext);
  }
  if ("kernel object" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Kernel Object';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/KernelObject", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/KernelObject/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/KernelObject/FIX", value:fixtext);
  }
  if ("sam" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit SAM';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SAM", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SAM/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SAM/FIX", value:fixtext);
  }
  if ("certification services" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Certification Services';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/CertificationServices", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/CertificationServices/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/CertificationServices/FIX", value:fixtext);
  }
  if ("application generated" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Application Generated';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGenerated", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGenerated/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGenerated/FIX", value:fixtext);
  }
  if ("handle manipulation" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Handle Manipulation';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/HandleManipulation", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/HandleManipulation/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/HandleManipulation/FIX", value:fixtext);
  }
  if ("file share" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit File Share';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/FileShare", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/FileShare/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/FileShare/FIX", value:fixtext);
  }
  if ("filtering platform packet drop" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Filtering Platform Packet Drop';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPacketDrop", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPacketDrop/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPacketDrop/FIX", value:fixtext);
  }
  if ("filtering platform connection" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Filtering Platform Connection';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformConnection", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformConnection/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformConnection/FIX", value:fixtext);
  }
  if ("other object access events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Object Access Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherObjectAccessEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherObjectAccessEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherObjectAccessEvents/FIX", value:fixtext);
  }
  if ("removable storage" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Removable Storage';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/RemovableStorage", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/RemovableStorage/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/RemovableStorage/FIX", value:fixtext);
  }
  if ("central policy staging" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Central Policy Staging';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Object Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/CentralPolicyStaging", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/CentralPolicyStaging/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/CentralPolicyStaging/FIX", value:fixtext);
  }
  if ("non sensitive privilege use" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Non Sensitive Privilege Use';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Privilege Use/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/NonSensitivePrivilegeUse", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/NonSensitivePrivilegeUse/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/NonSensitivePrivilegeUse/FIX", value:fixtext);
  }
  if ("other privilege use events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Privilege Use Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Privilege Use/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPrivilegeUseEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPrivilegeUseEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPrivilegeUseEvents/FIX", value:fixtext);
  }
  if ("sensitive privilege use" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Sensitive Privilege Use';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Privilege Use/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SensitivePrivilegeUse", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SensitivePrivilegeUse/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SensitivePrivilegeUse/FIX", value:fixtext);
  }
  if ("process creation" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Process Creation';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Detailed Tracking/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessCreation", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessCreation/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessCreation/FIXTEXT", value:fixtext);
  }
  if ("process termination" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Process Termination';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Detailed Tracking/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessTermination", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessTermination/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessTermination/FIXTEXT", value:fixtext);
  }
  if ("dpapi activity" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit DPAPI Activity';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Detailed Tracking/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DPAPIActivity", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DPAPIActivity/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DPAPIActivity/FIXTEXT", value:fixtext);
  }
  if ("rpc events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit RPC Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Detailed Tracking/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/RPCEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/RPCEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/RPCEvents/FIXTEXT", value:fixtext);
  }
  if ("plug and play events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit PNP Activity';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Detailed Tracking/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/PnPEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/PnPEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/PnPEvents/FIX", value:fixtext);
  }
  if ("authentication policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Authentication Policy Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/AuthenticationPolicyChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthenticationPolicyChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthenticationPolicyChange/FIX", value:fixtext);
  }
  if ("authorization policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Authorization Policy Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/AuthorizationPolicyChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthorizationPolicyChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthorizationPolicyChange/FIX", value:fixtext);
  }
  if ("mpssvc rule-level policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit MPSSVC Rule-Level Policy Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/MPSSVCRuleLevelPolicyChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/MPSSVCRuleLevelPolicyChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/MPSSVCRuleLevelPolicyChange/FIX", value:fixtext);
  }
  if ("filtering platform policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Filtering Platform Policy Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPolicyChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPolicyChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPolicyChange/FIX", value:fixtext);
  }
  if ("other policy change events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Policy Change Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPolicyChangeEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPolicyChangeEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPolicyChangeEvents/FIX", value:fixtext);
  }
  if ("audit policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Audit Policy Change';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Policy Change/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/AuditPolicyChange", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/AuditPolicyChange/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/AuditPolicyChange/FIX", value:fixtext);
  }
  if ("user account management" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit User Account Management';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/UserAccountManagement", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/UserAccountManagement/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/UserAccountManagement/FIX", value:fixtext);
  }
  if ("computer account management" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Computer Account Management';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/ComputerAccountManagement", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/ComputerAccountManagement/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/ComputerAccountManagement/FIX", value:fixtext);
  }
  if ("security group management" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Security Group Management';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityGroupManagement", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityGroupManagement/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityGroupManagement/FIX", value:fixtext);
  }
  if ("distribution group management" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Distribution Group Management';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DistributionGroupManagement", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DistributionGroupManagement/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DistributionGroupManagement/FIX", value:fixtext);
  }
  if ("application group management" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Application Group Management';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGroupManagement", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGroupManagement/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGroupManagement/FIX", value:fixtext);
  }
  if ("other account management events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Account Management Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Management/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountManagementEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountManagementEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountManagementEvents/FIX", value:fixtext);
  }
  if ("directory service access" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Directory Service Access';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/DS Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceAccess", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceAccess/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceAccess/FIX", value:fixtext);
  }
  if ("directory service changes" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Directory Service Changes';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/DS Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceChanges", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceChanges/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceChanges/FIX", value:fixtext);
  }
  if ("  directory service replication" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Directory Service Replication';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/DS Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceReplication", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceReplication/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceReplication/FIX", value:fixtext);
  }
  if ("detailed directory service replication" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Detailed Directory Service Replication';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/DS Access/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/DetailedDirectoryServiceReplication", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/DetailedDirectoryServiceReplication/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/DetailedDirectoryServiceReplication/FIX", value:fixtext);
  }
  if ("kerberos service ticket operations" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Kerberos Service Ticket Operations';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Logon/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosServiceTicketOperations", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosServiceTicketOperations/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosServiceTicketOperations/FIX", value:fixtext);
  }
  if ("other account logon events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Account Logon Events';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Logon/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountLogonEvents", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountLogonEvents/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountLogonEvents/FIX", value:fixtext);
  }
  if ("kerberos authentication service" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Kerberos Authentication Service';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Logon/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosAuthenticationService", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosAuthenticationService/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosAuthenticationService/FIX", value:fixtext);
  }
  if ("credential validation" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Credential Validation';
    fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit Policies/Account Logon/' + name;
    set_kb_item(name:"WMI/AdvancedPolicy/CredentialValidation", value:val);
    set_kb_item(name:"WMI/AdvancedPolicy/CredentialValidation/NAME", value:name);
    set_kb_item(name:"WMI/AdvancedPolicy/CredentialValidation/FIX", value:fixtext);
  }
}

exit(0);
