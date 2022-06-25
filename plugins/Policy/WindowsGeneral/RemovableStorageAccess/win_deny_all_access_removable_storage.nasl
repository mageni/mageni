##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_deny_all_access_removable_storage.nasl 9961 2018-05-25 13:02:30Z emoss $
#
# Check value for All Removable Storage classes: Deny all access
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
  script_oid("1.3.6.1.4.1.25623.1.0.312523");
  script_version("$Revision: 9961 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-25 15:02:30 +0200 (Fri, 25 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-23 15:59:18 +0200 (Wed, 23 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: All Removable Storage classes: Deny all access');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'All Removable Storage classes: Deny all access' on Windows hosts (at least Windows 7). 

The policy setting takes precedence over any individual removable storage policy 
settings. To manage individual classes, use the policy settings available for each 
class. If you enable this policy setting, no access is allowed to any removable 
storage class.
If you disable or do not configure this policy setting, write and read accesses 
are allowed to all removable storage classes.");
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

type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Windows\\RemovableStorageDevices';
item = 'Deny_All';
value = registry_get_dword(key:key, item:item, type:type);
if( value == ''){
  value = 'none';
}
policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);

exit(0);