##############################################################################
# OpenVAS Vulnerability Test
# $Id: win10_allowtelemetry.nasl 10961 2018-08-14 14:21:06Z emoss $
#
# Check value for Allow Telemetry
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
  script_oid("1.3.6.1.4.1.25623.1.0.312232");
  script_version("$Revision: 10961 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 16:21:06 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-04-23 12:03:04 +0200 (Mon, 23 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Allow Telemetry');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");
	script_add_preference(name:"Value", type:"radio", value:"0;1;2;3");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name:"summary", value:"This policy setting determines the amount of
Windows diagnostic data sent to Microsoft. A value of 0 (Security) will send minimal
data to Microsoft to keep Windows secure.
A value of 1 (Basic) sends the same data as a value of 0, plus a very
limited amount of diagnostic data.
A value of 2 (Enhanced) sends the same data as a value of 1, plus additional data.
A value of 3 (Full) sends the same data as a value of 2, plus advanced diagnostics data.");
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

title = 'Allow Telemetry';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/
Data Collection and Preview Builds/' + title;
type = 'HKLM';
key = 'SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection';
item = 'AllowTelemetry';
value = registry_get_dword(key:key, item:item, type:type);
default = script_get_preference('Value');

if(!value){
  value = '3';
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