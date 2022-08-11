##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_hardened_unc_path.nasl 10797 2018-08-06 14:54:44Z emoss $
#
# Check value for Hardened UNC Paths
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
  script_oid("1.3.6.1.4.1.25623.1.0.312570");
  script_version("$Revision: 10797 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 16:54:44 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-21 15:08:37 +0200 (Thu, 21 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Hardened UNC Paths');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy
'Hardened UNC Paths' on Windows hosts (at least Windows 7).

The setting configures secure access to UNC paths.
If enabled, Windows only allows access to the specified UNC paths after
fulfilling additional security requirements.

Note: This test only checks settings for following paths:
\\*\NETLOGON and \\*\SYSVOL.");
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
Older versions of Microsoft Windows are not supported any more.
Please update the system.');
  exit(0);
}

title = 'Hardened UNC Paths';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Network/Network Provider/' + title;
type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths';
item1 = '\\\\*\\NETLOGON';
item2 = '\\\\*\\SYSVOL';

value1 = registry_get_sz(key:key, item:item1, type:type);
if(!value1){
  value1 = 'none';
}
value2 = registry_get_sz(key:key, item:item2, type:type);
if(!value2){
  value2 = 'none';
}

value = item1 + ': ' + value1 + '\n' + item2 + ': ' + value2;

if(('RequireMutualAuthentication=1, RequireIntegrity=1' >< value1) &&
  ('RequireMutualAuthentication=1, RequireIntegrity=1' >< value2)){
  compliant = 'yes';
}else{
  compliant = 'no';
}

default = 'NETLOGON: Require Mutual Authentication, Require Integrity';
default += 'SYSVOL: Require Mutual Authentication, Require Integrity';

policy_logging(text:'"' + title + '" is set to: ' + value);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);

exit(0);