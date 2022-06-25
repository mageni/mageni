###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_sizer_microsoft_sharepoint_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# HPE Sizing for Microsoft SharePoint Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809455");
  script_version("$Revision: 10913 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-17 16:22:36 +0530 (Mon, 17 Oct 2016)");
  script_name("HPE Sizing for Microsoft SharePoint Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE Sizing Tool for Microsoft SharePoint.

  The script logs in via smb, searches for 'HPE Sizer for  Microsoft SharePoint'
  in the registry, gets version and installation path information from the
  registry.");

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
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HPE Sizer for Microsoft SharePoint" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!hpPath){
        hpPath = "Couldn find the install location from registry";
      }

      set_kb_item(name:"HPE/sizer/microsoft/sharepoint/Win/Ver", value:hpVer);

      if("SharePoint 2010" >< hpName)
      {
        register_and_report_cpe( app:hpName, ver:hpVer, base:"cpe:/a:hp:sizer_for_microsoft_sharepoint_2010:", expr:"^([0-9.]+)", insloc:hpPath );
      }
      if("SharePoint 2013" >< hpName)
      {
        register_and_report_cpe( app:hpName, ver:hpVer, base:"cpe:/a:hp:sizer_for_microsoft_sharepoint_2013:", expr:"^([0-9.]+)", insloc:hpPath );
      }
    }
  }
}
exit(0);
