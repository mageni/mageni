###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_imc_detect.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# HP Intelligent Management Center (iMC) Version Detection (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809282");
  script_version("$Revision: 12974 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2016-09-22 16:43:00 +0530 (Thu, 22 Sep 2016)");
  script_name("HP Intelligent Management Center (iMC) Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  HP Intelligent Management Center (iMC).

  The script logs in via smb, searches for 'HP Intelligent Management Center' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

##Key based on architecture
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key(key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    hpName = registry_get_sz(key:key + item, item:"DisplayName");
    if("HP Intelligent Management Center" >< hpName || "HPE Intelligent Management Center" >< hpName)
    {
      hpPath = registry_get_sz(key:key + item, item:"UninstallString");
      if(hpPath)
      {
        hpPath = eregmatch(pattern:"(.*iMC)\\deploy\\jdk", string:hpPath);
        logPath = hpPath[1] + "\deploy\log\deploylog.txt";
        install = hpPath[1];
        txtRead = smb_read_file(fullpath:logPath, offset:0, count:1000);

        fileVer = eregmatch(pattern:"Version: iMC PLAT ([0-9.]+ \([A-Za-z0-9]+)\)", string:txtRead);
        hpVer = ereg_replace(pattern:"\(", replace:"", string:fileVer[1]);
      }

      if(!hpVer)
      {
        ##Version from registry is only Major like 7.3
        hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        hpPath = eregmatch(pattern:".*.exe", string:hpPath);
        install = hpPath[0];
        if(!hpPath){
          hpPath = "Couldn find the install location from registry";
        }
      }

      if(hpVer)
      {
        hpVer = ereg_replace(pattern:" ", string:hpVer, replace: ".");

        set_kb_item(name:"HPE/iMC/Win/Ver", value:hpVer);

        cpe = build_cpe(value:hpVer, exp:"([0-9A-Z. ]+)", base:"cpe:/a:hp:intelligent_management_center:");
        if(isnull(cpe))
          cpe = "cpe:/a:hp:intelligent_management_center";

        register_product(cpe:cpe, location:install);

        log_message(data: build_detection_report(app: "HP Intelligent Management Center",
                                                 version: hpVer,
                                                 install: install,
                                                 cpe: cpe,
                                                 concluded: hpVer));
        exit(0);
      }
    }
  }
}
