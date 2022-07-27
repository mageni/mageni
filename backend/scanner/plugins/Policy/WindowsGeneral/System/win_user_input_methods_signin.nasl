##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_user_input_methods_signin.nasl 10819 2018-08-07 14:11:07Z emoss $
#
# Check value for Disallow copying of user input methods to the system
# account for sign-in
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
  script_oid("1.3.6.1.4.1.25623.1.0.312636");
  script_version("$Revision: 10819 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 16:11:07 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 14:04:55 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Disallow copying of user input methods to the system account for sign-in');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_add_preference(name:"Value", type:"radio", value:"1;0");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy
'Disallow copying of user input methods to the system account for sign-in' on Windows hosts (at
least Windows 8.1).

The setting prevents automatic copying of user input methods to the system account for use on the
sign-in screen. The user is restricted to the set of input methods that are enabled in the system
account.");
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
These setting only applies to Windows 8.1 or higher systems.');
  exit(0);
}

title = 'Disallow copying of user input methods to the system account for sign-in';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Locale Services/' + title;
type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Control Panel\\International';
item = 'BlockUserInputMethodsForSignIn';
default = script_get_preference('Value');
value = registry_get_dword(key:key, item:item, type:type);

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