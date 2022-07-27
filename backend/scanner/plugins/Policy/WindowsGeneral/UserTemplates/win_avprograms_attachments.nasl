##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_avprograms_attachments.nasl 10989 2018-08-15 14:57:51Z emoss $
#
# Check value for Notify antivirus programs when opening attachments
# (users listed in HKU)
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
  script_oid("1.3.6.1.4.1.25623.1.0.312504");
  script_version("$Revision: 10989 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-15 16:57:51 +0200 (Wed, 15 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-28 16:22:17 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Notify antivirus programs when opening attachments');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_add_preference(name:"Value", type:"radio", value:"3;1");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"This test checks the setting for policy
'Notify antivirus programs when opening attachments' on Windows hosts (at
least Windows 7).

The setting manages the behavior for notifying registered antivirus programs.
If multiple programs are registered, they will all be notified. If the
registered antivirus program already performs on-access checks or scans files as
they arrive on the computers email server, additional calls would be redundant.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("wmi_user.inc");
include("secpod_smb_func.inc");

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

title = 'Notify antivirus programs when opening attachments';
fixtext = 'Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Attachment Manager/' + title;
type = 'HKU';
item = 'ScanWithAntiVirus';
default = script_get_preference('Value');
v = make_array();

uids = registry_enum_keys(key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList', type:'HKLM');
foreach uid (uids){
  if(uid =~ "S-1-5-21-"){
      if(registry_key_exists(key:uid, type:'HKU')){
      key = uid + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments';
      value = registry_get_dword(key:key, item:item, type:type);
      if(!value){
        value = '1';
      }
      v[uid] = value;
    }
  }
}

compliant = 'yes';
foreach entry (keys(v)){
  if(v[entry] != default){
    compliant = 'no';
  }
}

policy_logging(text:'"' + title + '" is set to: ' + v);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:v);
policy_set_compliance(compliant:compliant);

exit(0);