###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_horizon_client_detect_win.nasl 10945 2018-08-14 06:57:51Z santu $
#
# VMware Horizon Client Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813821");
  script_version("$Revision: 10945 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 08:57:51 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-10 14:55:05 +0530 (Fri, 10 Aug 2018)");
  script_name("VMware Horizon Client Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  VMware Horizon Client.

  The script logs in via smb, searches registry for VMware Horizon Client
  and gets the version from 'DisplayVersion' string.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://my.vmware.com");
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

## same key exist for 32 and 64 bit application
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  vmhrName = registry_get_sz(key:key + item, item:"DisplayName");

  if("VMware Horizon Client" >< vmhrName)
  {
    vmhrVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(vmhrVer)
    {
      vmhrPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!vmhrPath){
        vmhrPath = "Unable to find the install location from registry";
      }

      set_kb_item(name:"VMware/HorizonClient/Win/Ver", value:vmhrVer);

      cpe = build_cpe(value:vmhrVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:horizon_view_client:");
      if(isnull(cpe))
        cpe = "cpe:/a:vmware:horizon_view_client";

      register_product(cpe:cpe, location:vmhrPath);
      log_message(data: build_detection_report(app:"VMware Horizon Client",
                                                 version: vmhrVer,
                                                 install: vmhrPath,
                                                 cpe: cpe,
                                                 concluded: vmhrVer));
      exit(0);
    }
  }
}
exit(0);
