###############################################################################
# OpenVAS Vulnerability Test
# $Id: win_AdvancedPolicySettings.nasl 12197 2018-11-02 08:48:38Z emoss $
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
  script_oid("1.3.6.1.4.1.25623.1.0.109001");
  script_version("$Revision: 12197 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 09:48:38 +0100 (Fri, 02 Nov 2018) $");
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

  script_tag(name:"summary", value:"Read all Windows Advanced Policy Security Settings (Windows)");

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

AdvancedPolicy = split(AdvancedPolicy, keep:FALSE);
foreach pol (AdvancedPolicy) {
  if ("security system extension" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemSecurityExtension", value:val);
  }
  if ("system integrity" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SystemIntegrity", value:val);
  }
  if ("ipsec driver" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecDriver", value:val);
  }
  if ("other system events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherSystemEvents", value:val);
  }
  if ("security state change" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityStateChange", value:val);
  }
  if ("  logon " >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/Logon", value:val);
  }
  if ("  logoff " >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/Logoff", value:val);
  }
  if ("account lockout" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/AccountLockout", value:val);
  }
  if ("ipsec main mode" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecMainMode", value:val);
  }
  if ("ipsec quick mode" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecQuickMode", value:val);
  }
  if ("ipsec extended mode" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/IPsecExtendedMode", value:val);
  }
  if ("special logon" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SpecialLogon", value:val);
  }
  if ("other logon/logoff events" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit Other Logon/Logoff Events';
    set_kb_item(name:"WMI/AdvancedPolicy/OtherLogonLogoffEvents", value:val);
  }
  if ("network policy server" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/NetworkPolicyServer", value:val);
  }
  if ("user / device claims" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit User / Device Claims';
    set_kb_item(name:"WMI/AdvancedPolicy/UserDeviceClaims", value:val);
  }
  if ("group membership" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/GroupMembership", value:val);
  }
  if ("file system" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/FileSystem", value:val);
  }
  if ("registry" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/Registry", value:val);
  }
  if ("kernel object" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/KernelObject", value:val);
  }
  if ("sam" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SAM", value:val);
  }
  if ("certification services" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/CertificationServices", value:val);
  }
  if ("application generated" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGenerated", value:val);
  }
  if ("handle manipulation" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/HandleManipulation", value:val);
  }
  if ("file share" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/FileShare", value:val);
  }
  if ("filtering platform packet drop" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPacketDrop", value:val);
  }
  if ("filtering platform connection" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformConnection", value:val);
  }
  if ("other object access events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherObjectAccessEvents", value:val);
  }
  if ("removable storage" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/RemovableStorage", value:val);
  }
  if ("central policy staging" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/CentralPolicyStaging", value:val);
  }
  if ("non sensitive privilege use" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/NonSensitivePrivilegeUse", value:val);
  }
  if ("other privilege use events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPrivilegeUseEvents", value:val);
  }
  if ("sensitive privilege use" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SensitivePrivilegeUse", value:val);
  }
  if ("process creation" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessCreation", value:val);
  }
  if ("process termination" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/ProcessTermination", value:val);
  }
  if ("dpapi activity" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DPAPIActivity", value:val);
  }
  if ("rpc events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/RPCEvents", value:val);
  }
  if ("plug and play events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/PnPEvents", value:val);
  }
  if ("authentication policy change" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthenticationPolicyChange", value:val);
  }
  if ("authorization policy change" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/AuthorizationPolicyChange", value:val);
  }
  if ("mpssvc rule-level policy change" >< tolower(pol) ){
    val = auditing(pol);
    name = 'Audit MPSSVC Rule-Level Policy Change';
    set_kb_item(name:"WMI/AdvancedPolicy/MPSSVCRuleLevelPolicyChange", value:val);
  }
  if ("filtering platform policy change" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/FilteringPlatformPolicyChange", value:val);
  }
  if ("other policy change events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherPolicyChangeEvents", value:val);
  }
  if ("audit policy change" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/AuditPolicyChange", value:val);
  }
  if ("user account management" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/UserAccountManagement", value:val);
  }
  if ("computer account management" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/ComputerAccountManagement", value:val);
  }
  if ("security group management" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/SecurityGroupManagement", value:val);
  }
  if ("distribution group management" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DistributionGroupManagement", value:val);
  }
  if ("application group management" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/ApplicationGroupManagement", value:val);
  }
  if ("other account management events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountManagementEvents", value:val);
  }
  if ("directory service access" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceAccess", value:val);
  }
  if ("directory service changes" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceChanges", value:val);
  }
  if ("  directory service replication" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DirectoryServiceReplication", value:val);
  }
  if ("detailed directory service replication" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/DetailedDirectoryServiceReplication", value:val);
  }
  if ("kerberos service ticket operations" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosServiceTicketOperations", value:val);
  }
  if ("other account logon events" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/OtherAccountLogonEvents", value:val);
  }
  if ("kerberos authentication service" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/KerberosAuthenticationService", value:val);
  }
  if ("credential validation" >< tolower(pol) ){
    val = auditing(pol);
    set_kb_item(name:"WMI/AdvancedPolicy/CredentialValidation", value:val);
  }
}

exit(0);