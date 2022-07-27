###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# HPE LoadRunner Version Detection (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810327");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-01-10 11:07:22 +0530 (Tue, 10 Jan 2017)");
  script_name("HPE LoadRunner Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE LoadRunner.

  The script logs in via smb, searches for 'HP LoadRunner' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HP LoadRunner" >< hpName || "HPE LoadRunner" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!hpPath){
          hpPath = "Couldn find the install location from registry";
        }

        set_kb_item(name:"HPE/LoadRunner/Win/Ver", value:hpVer);

        cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:loadrunner:");
        if(isnull(cpe))
          cpe = "cpe:/a:hp:loadrunner";

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"HPE/LoadRunner64/Win/Ver", value:hpVer);

          cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:loadrunner:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:hp:loadrunner:x64";
        }

        register_product(cpe:cpe, location:hpPath);

        log_message(data: build_detection_report(app: "HPE LoadRunner",
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer));
    }
  }
}
