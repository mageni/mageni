##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_signin_last_user.nasl 10989 2018-08-15 14:57:51Z emoss $
#
# Check value for Sign-in last interactive user automatically after a
# system-initiated restart
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
  script_oid("1.3.6.1.4.1.25623.1.0.312382");
  script_version("$Revision: 10989 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-15 16:57:51 +0200 (Wed, 15 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-28 08:13:43 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Sign-in last interactive user automatically');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_add_preference(name:"Value", type:"radio", value:"1;0");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"This test checks the setting for policy
'Sign-in last interactive user automatically after a system-initiated restart'
on Windows hosts (at least Windows 8.1).

The setting determines whether a device will automatically sign-in the last
interactive user after Windows Update restarts the system.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

if(get_kb_item("SMB/WindowsVersion") < "6.3"){
  policy_logging(text:'Host is not at least a Microsoft Windows 8.1 system.
This setting applies to Windows 8.1 or higher versions only.');
  exit(0);
}

title = 'Sign-in last interactive user automatically after a system-initiated restart';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/
Windows Logon Options/' + title;
type = 'HKLM';
key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
item = 'DisableAutomaticRestartSignOn';
value = registry_get_dword(key:key, item:item, type:type);
default = script_get_preference('Value');

if(!value){
  value = '0';
}

if(int(value) == int(default)){
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