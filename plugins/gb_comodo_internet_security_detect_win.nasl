###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_internet_security_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Comodo Internet Security Version Detection (Windows)
#
# Authors:
# Arun kallavi <karun@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-10
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803683");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-07-05 13:15:00 +0530 (Fri, 05 Jul 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Comodo Internet Security Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of Comodo Internet Security.

The script logs in via smb, searches for Comodo Internet Security in the
registry and gets the version from registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key_list = make_list("SOFTWARE\ComodoGroup\CDI\",
                     "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");

if(isnull(key_list)){
    exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\COMODO\CIS")){
    exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"Product Name");
    if(!appName){
      appName = registry_get_sz(key:key + item, item:"DisplayName");
    }

    if("COMODO Internet Security" >< appName)
    {
      cisPath = registry_get_sz(key:key + item, item:"InstallProductPath");
      if(!cisPath){
        cisPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!cisPath){
          cisPath = "Could not find the install Location from registry";
        }
      }

      cisVer = registry_get_sz(key:key + item, item:"Product Version");
      if(!cisVer){
        cisVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      }

      if(cisVer)
      {
        set_kb_item(name:"Comodo/InternetSecurity/Win/Ver", value:cisVer);

        cpe = build_cpe(value:cisVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:comodo:comodo_internet_security:");
        if(isnull(cpe))
          cpe = "cpe:/a:comodo:comodo_internet_security";

        if("x64" >< os_arch)
        {
          set_kb_item(name:"Comodo/InternetSecurity64/Win/Ver", value:cisVer);

          cpe = build_cpe(value:cisVer, exp:"^([0-9.]+)",
                          base:"cpe:/a:comodo:comodo_internet_security:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:comodo:comodo_internet_security:x64";
        }

        register_product(cpe:cpe, location:cisPath);
        log_message(data: build_detection_report(app: "Comodo Internet Security",
                                                 version: cisVer,
                                                 install: cisPath,
                                                 cpe: cpe,
                                                 concluded: cisVer));
        ## To improve performance by avoiding extra iteration over uninstall path
        exit(0);
      }
    }
  }
}
