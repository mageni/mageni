###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wmi_eventlog.nasl 11392 2018-09-14 14:36:38Z cfischer $
#
# Get Windows Eventlog Entries over WMI
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96204");
  script_version("$Revision: 11392 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 16:36:38 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows Eventlog Entries over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_add_preference(name:"Maximum number of log lines", type:"entry", value:"0");

  script_tag(name:"summary", value:"Get Windows Eventlog Entries over WMI");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

RecNumber = script_get_preference("Maximum number of log lines");
if (RecNumber <= 0) exit(0);
if (RecNumber > 100) RecNumber = 100;

infos = kb_smb_wmi_connectinfo();
if (!infos) exit(0);

handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
if(!handle){
  exit(0);
}

AppRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber FROM Win32_NTLogEvent WHERE LogFile = 'Application'");
AppRecNumber = split(AppRecNumber, keep:FALSE);
var = split(AppRecNumber[1], sep:"|", keep:FALSE);
AppFirstRecNumber = var[1];

SecRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber FROM Win32_NTLogEvent WHERE LogFile = 'Security'");
SecRecNumber = split(SecRecNumber, keep:FALSE);
var = split(SecRecNumber[1], sep:"|", keep:FALSE);
SecFirstRecNumber = var[1];

SysRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber FROM Win32_NTLogEvent WHERE LogFile = 'System'");
SysRecNumber = split(SysRecNumber, keep:FALSE);
var = split(SysRecNumber[1], sep:"|", keep:FALSE);
SysFirstRecNumber = var[1];

set_kb_item(name:"WMI/SysFirstRecNumber", value:SysFirstRecNumber);#TEST

if(AppFirstRecNumber != "1"){
  if(int(AppFirstRecNumber) > int(RecNumber)){
    AppRecNumber = int(AppFirstRecNumber) - int(RecNumber);
  } else {
    AppRecNumber = int(AppFirstRecNumber);
  }
  set_kb_item(name:"WMI/AppRecNumber", value:AppRecNumber);#TEST
  AppQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile = 'Application' AND RecordNumber >= '" + AppRecNumber + "'";
  Application = wmi_query(wmi_handle:handle, query:AppQuery);
}

if(SecFirstRecNumber != "1"){
  if(int(SecFirstRecNumber) > int(RecNumber)){
    SecRecNumber = int(SecFirstRecNumber) - int(RecNumber);
  } else {
    SecRecNumber = int(SecFirstRecNumber);
  }
  SecQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile = 'Security' AND RecordNumber >= '" + SecRecNumber + "'";
  Security = wmi_query(wmi_handle:handle, query:SecQuery);
}

if(SysFirstRecNumber != "1"){
  if(int(SysFirstRecNumber) > int(RecNumber)){
    SysRecNumber = int(SysFirstRecNumber) - int(RecNumber);
  } else {
    SysRecNumber = int(SysFirstRecNumber);
  }
  SysQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile = 'System' AND RecordNumber >= '" + SysRecNumber + "'";
  System = wmi_query(wmi_handle:handle, query:SysQuery);
}

if (Application)log_message(port:0, proto:"MS-Eventlog/Application", data:Application);
if (Security)log_message(port:0, proto:"MS-Eventlog/Security", data:Security);
if (System)log_message(port:0, proto:"MS-Eventlog/System", data:System);

wmi_close(wmi_handle:handle);
exit(0);
