##############################################################################
# OpenVAS Vulnerability Test
# $Id: defav_enable_pua.nasl 10136 2018-06-08 12:19:06Z emoss $
#
# Check value for Windows Defender AV: Turn on Windows Defender protection against Potentially Unwanted Applications
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
  script_oid("1.3.6.1.4.1.25623.1.0.312301");
  script_version("$Revision: 10136 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 14:19:06 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-07 14:52:55 +0200 (Thu, 07 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows Defender AV: Windows Defender protection against PUA');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'Turn on Windows Defender protection against Potentially Unwanted Applications' 
on Windows hosts (at least Windows 8.1).

If this feature is enabled, Potentially Unwanted Application (PUA) protection 
blocking takes effect on endpoint clients after the next signature update or 
computer restart. Signature updates take place daily under typical circumstances. 
PUA will be blocked and automatically quarantined.");
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
Older versions of Windows do not supported this setting.');
  exit(0);
}

title = 'Turn on Windows Defender protection against Potentially Unwanted Applications';
type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Windows Defender\\MpEngine';
item = 'MpEnablePus';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/MS Security Guide/Turn on Windows Defender protection against Potentially Unwanted Applications';

value = registry_get_sz(key:key, item:item, type:type);
if( value == ''){
  value = 'none';
}

policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);

exit(0);