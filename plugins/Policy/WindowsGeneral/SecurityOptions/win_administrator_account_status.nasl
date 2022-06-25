##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_administrator_account_status.nasl 10649 2018-07-27 07:16:55Z emoss $
#
# Check value for Accounts: Administrator account status (WMI)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.312364");
  script_version("$Revision: 10649 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:16:55 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-04 10:51:31 +0200 (Fri, 04 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Accounts: Administrator account status');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl");
  script_add_preference(name:"Status", type:"entry", value:"Degraded");
  script_mandatory_keys("Compliance/Launch");
  script_require_keys("WMI/access_successful");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'Accounts: Administrator account status' on Windows hosts (at least Windows 7).

The security setting determines whether the local Administrator account is 
enabled or disabled.
The following conditions prevent disabling the Administrator account, even if 
this security setting is disabled:

- The Administrator account is currently in use

- The Administrators group has no other members

- All other members of the Administrators group are:

  - Disabled
  
  - Listed in the Deny log on locally User Rights Assignment

If the Administrator account is disabled, you cannot enable it if the password 
does not meet requirements. In this case, another member of the Administrators 
group must reset the password.");
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

title = 'Accounts: Administrator account status';
select = 'Status';
name = 'Administrator';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/' + title;
default = script_get_preference('Status');

result = win32_useraccount(select:select,name:name);
lines = split(result, keep:FALSE);
status = split(lines[1],sep:'|', keep:FALSE);
value = status[2];
if( value == ''){
  value = "Error";
}

if(tolower(chomp(value)) == tolower(default)){
  compliant = 'yes';
}else{
  compliant = 'no';
}

policy_logging(text:'"' + title + '" is set to: ' + value);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);

exit(0);