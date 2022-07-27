###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_sizer_microsoft_skype_business_server_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# HPE Sizer for Microsoft Skype for Business Server Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809457");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-17 16:22:36 +0530 (Mon, 17 Oct 2016)");
  script_name("HPE Sizer for Microsoft Skype for Business Server Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE Sizer for Microsoft Skype for Business Server.

  The script logs in via smb, searches for 'HPE Sizer for Microsoft Skype for
  Business Server' in the registry, gets version and installation path
  information from the registry.");

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

if(!registry_key_exists(key:"SOFTWARE\Hewlett Packard Enterprise\Sizers\Skype for Business Planning Tool") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Hewlett Packard Enterprise\Sizers\Skype for Business Planning Tool")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

##Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HPE Sizer for Microsoft Skype for Business Server" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!hpPath){
        hpPath = "Couldn find the install location from registry";
      }

      set_kb_item(name:"HPE/Sizer/Microsoft/Skype/Business/Server/Win/Ver", value:hpVer);

      ##Currently only Microsoft Skype for Business Server 2015 is available
      if("Server 2015" >< hpName)
      {
        cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:sizer_for_microsoft_skype_for_business_server_2015:");
        if(isnull(cpe))
          cpe = "cpe:/a:hp:sizer_for_microsoft_skype_for_business_server_2015";
      }

      if(cpe)
      {
        register_product(cpe:cpe, location:hpPath);

        log_message(data: build_detection_report(app: hpName,
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer));
      }
    }
  }
}
