##############################################################################
# OpenVAS Vulnerability Test
# $Id: win10_rename_guest_account.nasl 10649 2018-07-27 07:16:55Z emoss $
#
# Check value for Accounts: Rename guest account (WMI)
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
  script_oid("1.3.6.1.4.1.25623.1.0.312194");
  script_version("$Revision: 10649 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:16:55 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-04 14:00:00 +0200 (Fri, 04 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Accounts: Rename guest account');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_require_keys("WMI/access_successful");
  script_tag(name: "summary", value: "The Accounts: Rename guest account policy 
setting determines whether a different account name is associated with the 
security identifier (SID) for the Guest account.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

WindowsName = get_kb_item("SMB/WindowsName");
if('windows 10' >!< tolower(WindowsName)){
  policy_logging(text:'Host is not a Microsoft Windows 10 System.');
  exit(0); 
}

host = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();
domain  = kb_smb_domain();
if( domain ) usrname = domain + "\" + usrname;

handle = wmi_connect(host:host, username:usrname, password:passwd);
  if(!handle){
  policy_logging(text:'WMI Connect to host failed.');
  policy_set_kb(val:'error');
  wmi_close(wmi_handle:handle);
  exit(0);
}

title = 'Accounts: Rename guest account';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/' + title;
default = 'Guest';

query = "SELECT Name FROM Win32_UserAccount WHERE (SID LIKE 'S-1-5-21-%-501')";
res = wmi_query(wmi_handle:handle, query:query);
lines = split(res,keep:FALSE);
name = split(lines[1],sep:'|', keep:FALSE);
value = name[1];

if( value == ''){
  value = 'Guest';
}

if(tolower(chomp(value)) == tolower(default)){
  compliant = 'no';
}else{
  compliant = 'yes';
}

policy_logging(text:'"' + title + '" is set to: ' + value);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);
wmi_close(wmi_handle:handle);
exit(0);