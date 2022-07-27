###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panasonic_fpwin_pro_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Panasonic FPWIN Pro Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809028");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-09-01 13:08:12 +0530 (Thu, 01 Sep 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Panasonic FPWIN Pro Version Detection (Windows)");
  script_tag(name:"summary", value:"Detection of installed version
  of Panasonic FPWIN Pro on Windows.

  The script logs in via smb, searches for Panasonic FPWIN Pro in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Panasonic Electric Works Europe AG") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Panasonic Electric Works Europe AG") &&
   !registry_key_exists(key:"SOFTWARE\Panasonic-ID SUNX Control") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Panasonic-ID SUNX Control")){
  exit(0);
}

## if os is 32 bit iterate over common path
if("x86" >< osArch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

#currently 64 bit app is not available
else if("x64" >< osArch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  fpwinName = registry_get_sz(key:key + item, item:"DisplayName");

  if(fpwinName =~ "FPWIN Pro ([0-9]+)")
  {

    fpwinVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    fpwinPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!fpwinPath){
      fpwinPath = "Couldn find the install location from registry";
    }

    if(fpwinVer)
    {
      set_kb_item(name:"Panasonic/FPWIN/Pro/Win/Ver", value:fpwinVer);

      cpe = build_cpe(value:fpwinVer, exp:"^([0-9.]+)", base:"cpe:/a:panasonic:fpwin_pro:");
      if(!cpe)
        cpe = "cpe:/a:panasonic:fpwin_pro";

      register_product(cpe:cpe, location:fpwinPath);
      log_message(data: build_detection_report(app: "Panasonic FPWIN Pro",
                                               version: fpwinVer,
                                               install: fpwinPath,
                                               cpe: cpe,
                                               concluded: fpwinVer));
      exit(0);
    }
  }
}
