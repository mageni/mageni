##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_advsec_profile_inboundcon.nasl 10010 2018-05-29 14:43:35Z emoss $
#
# Check value for Windows Defender Firewall: Inbound connections
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
  script_oid("1.3.6.1.4.1.25623.1.0.312489");
  script_version("$Revision: 10010 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 16:43:35 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-28 09:58:39 +0200 (Mon, 28 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Windows Defender Firewall: Inbound connections');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'Windows Defender Firewall: Domain Profile: Inbound connections', 'Windows 
Defender Firewall: Private Profile: Inbound connections' 'Windows Defender 
Firewall: Public Profile: Inbound connections' on Windows hosts (at least 
Windows 7).

The policy determines the behaviour for inbound connections not matching an
inbound firewall rule.");
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

profiles = make_list("Domain", "Private", "Public");

foreach profile (profiles){
  type = 'HKLM';
  key = 'Software\\Policies\\Microsoft\\WindowsFirewall\\' + profile + 'Profile';
  item = 'DefaultInboundAction';
  value = registry_get_dword(key:key, item:item, type:type);
  if( value == ''){
    value = 'none';
  }
  set_kb_item(name:'Windows/FirewallAdvSec/InboundConnection/' + profile, value:string(value));
  if(value == 'none'){
    text += 'Unable to detect registry value ' + type + '\\' + key + '!' + item + '.\n';
  }else{
    text += 'Registry value ' + type + '\\' + key + '!' + item + ' is set to: ' + value + '\n';
  }
}

policy_logging(text:text);

exit(0);