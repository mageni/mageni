##############################################################################
# OpenVAS Vulnerability Test
# $Id: office2013_allow_insecure_apps_catalogs.nasl 9659 2018-04-27 11:55:11Z emoss $
#
# Check value for Allow Unsecure Apps and Catalogs
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
  script_oid("1.3.6.1.4.1.25623.1.0.312307");
  script_version("$Revision: 9659 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 13:55:11 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-17 09:42:28 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Office 2013: Allow Unsecure Apps and Catalogs');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
	script_require_keys("MS/Office/Ver");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: 'Check Setting "Allow Unsecure Apps and Catalogs" (Microsoft Office 2013).');
  exit(0);
}

include("smb_nt.inc"); 
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

Office_Ver = get_kb_item("MS/Office/Ver");
if(ereg(string:Office_Ver, pattern:"^15.0") != 1){
  policy_logging(text:'Unable to find Microsoft Office 2013 on Host System.');
  exit(0);
}

type = 'HKCU';
key = 'Software\\Policies\\Microsoft\\Office\\15.0\\wef\\trustedcatalogs';
item = 'requireserververification';
value = registry_get_dword(key:key, item:item, type:type);
if( value == ''){
  value = 'none';
}
policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);

exit(0);