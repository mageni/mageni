##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_use_wu_server_path.nasl 9659 2018-04-27 11:55:11Z emoss $
#
# Check value for Set the intranet update service for detecting updates
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
  script_oid("1.3.6.1.4.1.25623.1.0.312512");
  script_version("$Revision: 9659 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 13:55:11 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-17 09:42:28 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Set the intranet update service for detecting updates');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: 'Check Setting "Set the intranet update service for detecting updates" (Microsoft Windows).');
  exit(0);
}

include("smb_nt.inc"); 
include("policy_functions.inc");

type = 'HKLM';
key = 'Software\\Policies\\Microsoft\\Windows\\WindowsUpdate';
item = 'WUServer';
value = registry_get_dword(key:key, item:item, type:type);
if( value == ''){
  value = 'none';
}
policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);

exit(0);