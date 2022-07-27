##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_device_pk_init.nasl 10809 2018-08-07 11:19:51Z emoss $
#
# Check value for Support device authentication using certificate
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
  script_oid("1.3.6.1.4.1.25623.1.0.312285");
  script_version("$Revision: 10809 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 13:19:51 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 12:58:20 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Support device authentication using certificate');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");
  script_add_preference(name:"Value", type:"radio", value:"0;1");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 'Support device
authentication using certificate (behaviour)' on Windows hosts (at least Windows 10).

The setting controls the support for Kerberos to attempt authentication using the certificate for
the device to the domain.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

HostDetails = get_kb_list("HostDetails");
if("cpe:/o:microsoft:windows_10" >!< HostDetails){
  policy_logging(text:'Host is not a Microsoft Windows 10 system.
This setting applies to Windows 10 systems only.');
  exit(0);
}

title = 'Support device authentication using certificate';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Kerberos/' + title;
type = 'HKLM';
key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters';
item = 'DevicePKInitBehavior';
default = script_get_preference('Value');
value = registry_get_dword(key:key, item:item, type:type);

if(!value){
  value = '2';
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