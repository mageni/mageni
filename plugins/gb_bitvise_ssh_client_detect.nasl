###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitvise_ssh_client_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Bitvise SSH Client Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813385");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Client Version Detection (Windows)");
  script_tag(name:"summary", value:"Detects the installed version of
  Bitvise SSH Client.

  The script logs in via smb, searches for 'Bitvise SSH Client' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

##Currently only 32-bit application is available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  bitName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Bitvise SSH Client" >< bitName)
  {
    bitPath = registry_get_sz(key:key + item, item:"InstallSource");
    if(!bitPath){
      bitPath = "Couldn find the install location";
    }

    bitVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(bitVer)
    {
      set_kb_item(name:"BitviseSSH/Client/Win/Ver", value:bitVer);

      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitvise:ssh_client:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitvise:ssh_client";

      register_product(cpe:cpe, location:bitPath);

      log_message(data: build_detection_report(app: "Bitvise SSH Client",
                                               version: bitVer,
                                               install: bitPath,
                                               cpe: cpe,
                                               concluded: "Bitvise SSH Client " + bitVer));
    }
  }
}
exit(0);
