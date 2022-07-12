###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_detect_win.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Google Chrome Version Detection (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800120");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Google Chrome on Windows.

The script logs in via smb, searches for Google Chrome in the registry and gets
the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Google Chrome" >< appName)
  {
    chromeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(chromeVer)
    {
      chromePath = registry_get_sz(key:key + item, item:"InstallLocation");

      set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);

      cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
      if(isnull(cpe))
        cpe = "cpe:/a:google:chrome";

      # Used in gb_google_chrome_detect_portable_win.nasl to detect doubled detections
      set_kb_item(name:"GoogleChrome/Win/InstallLocations", value:tolower(chromePath));

      register_product(cpe: cpe, location: chromePath);
      log_message(data: build_detection_report(app: "Google Chrome",
                                               version: chromeVer,
                                               install: chromePath,
                                                   cpe: cpe,
                                             concluded: chromeVer));
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\";
if(!registry_key_exists(key:key)){
  exit(0);
}

enumKeys = registry_enum_keys(key:key);

foreach key (enumKeys)
{
  chromeVer = registry_get_sz(key:key + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome", item:"Version", type:"HKU");
  if(chromeVer)
  {
    chromePath = registry_get_sz(key:key + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome", item:"InstallLocation", type:"HKU");

    set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);

    cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
    if(isnull(cpe))
     cpe = "cpe:/a:google:chrome";

    # Used in gb_google_chrome_detect_portable_win.nasl to detect doubled detections
    set_kb_item(name:"GoogleChrome/Win/InstallLocations", value:tolower(chromePath));

    register_product(cpe: cpe, location: chromePath);
    log_message(data: build_detection_report(app: "Google Chrome",
                                             version: chromeVer,
                                             install: chromePath,
                                             cpe: cpe,
                                             concluded: chromeVer));


  }
}
