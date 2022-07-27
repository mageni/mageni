###############################################################################
# OpenVAS Vulnerability Test
# $Id: win_last_access_timestamp.nasl 12233 2018-11-06 15:01:14Z emoss $
#
# Read the status of NTFS MAC 'Last Access Timestamp'
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96047");
  script_version("$Revision: 12233 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 16:01:14 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-01-15 16:20:21 +0100 (Fri, 15 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Windows: Last Access Timestamp'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Policy");
  script_add_preference(name:"Value", type:"radio", value:"0;1");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"Read the status of NTFS MAC 'Last Access Timestamp'.");

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

title = 'Last Access Timestamp';
fixtext = 'Run following command in elevated command prompt: "fsutil behavior set disablelastaccess [0,1]"';
type = 'HKLM';
key = 'SYSTEM\\CurrentControlSet\\Control\\FileSystem';
item = 'NtfsDisableLastAccessUpdate';
default = script_get_preference('Value');
value = registry_get_dword(key:key, item:item, type:type);

if(value == ''){
  value = '-1';
}

if(value == default){
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