###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_exchange_server_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# Microsoft Exchange Server Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805114");
  script_version("$Revision: 10905 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-12-10 14:51:17 +0530 (Wed, 10 Dec 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Exchange Server Detection");

  script_tag(name:"summary", value:"This script detects the installed
  version of Microsoft Exchange Server and sets the result in KB.

  The script logs in via smb, searches for Exchange Server in the registry
  and gets the version from registry or file.");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange") &&
   !registry_key_exists(key:"SOFTWARE\Microsoft\ExchangeServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Microsoft Exchange Server 4.0, 5.0, 5.5, 2003, 2007, 2010, 2013, 2016
  if(appName =~ "Microsoft Exchange Server [0-9.]+" && "Language Pack" >!< appName)
  {
    ExVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ExVer)
    {
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        exit(0);
      }

      set_kb_item(name:"MS/Exchange/Server/Ver", value:ExVer);

      set_kb_item( name:"MS/Exchange/Server/installed", value:TRUE );

      if("Cumulative Update" >< appName)
      {
        set_kb_item(name:"MS/Exchange/Cumulative/Update", value:ExVer);
        set_kb_item(name:"MS/Exchange/Cumulative/Update/no", value:appName);
      }

      cpe = build_cpe(value:ExVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:");
      if(isnull(cpe))
        cpe = "cpe:/a:microsoft:exchange_server";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: appName,
                                               version: ExVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: ExVer));
    }
  }
}
