###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libre_office_detect_win.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# LibreOffice Version Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902398");
  script_version("$Revision: 10901 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of LibreOffice on Windows.

  The script logs in via smb, searches for LibreOffice in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!registry_key_exists(key:"SOFTWARE\LibreOffice")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\LibreOffice")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list){

  foreach item (registry_enum_keys(key:key)){

    officeName = registry_get_sz(key:key + item, item:"DisplayName");

    if("LibreOffice" >< officeName){

      officeVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!isnull(officeVer)){
        officePath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!officePath){
          officePath = "Could not able to get the install location";
        }

        set_kb_item(name:"LibreOffice/Win/Ver", value:officeVer);

        cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:");
        if(isnull(cpe))
          cpe = "cpe:/a:libreoffice:libreoffice";

        if("64" >< os_arch && "Wow6432Node" >!< key){

          set_kb_item(name:"LibreOffice64/Win/Ver", value:officeVer);
          cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:x64:");

          if(isnull(cpe))
            cpe = "cpe:/a:libreoffice:libreoffice:x64";
        }

        # Used in gb_libreoffice_detect_portable_win.nasl to avoid doubled detections.
        # We're also stripping a possible ending backslash away as the portable NVT is getting
        # the file path without the ending backslash from WMI.
        tmp_location = tolower(officePath);
        tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
        set_kb_item(name:"LibreOffice/Win/InstallLocations", value:tmp_location);

        register_product(cpe:cpe, location:officePath);
        log_message(port:0, data:build_detection_report(app:officeName, version:officeVer, install:officePath, cpe:cpe, concluded:officeVer));
      }
    }
  }
}

exit(0);
