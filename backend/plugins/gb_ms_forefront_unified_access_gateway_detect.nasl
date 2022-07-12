###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_forefront_unified_access_gateway_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Microsoft Forefront Unified Access Gateway (UAG) Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802746");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-13 10:46:45 +0530 (Fri, 13 Apr 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Forefront Unified Access Gateway (UAG) Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Forefront Unified Access Gateway.

The script logs in via smb, searches for Microsoft Forefront Unified Access
Gateway in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## Application is available as 64 bit only and it can be
## installed only on 64 bit OS
## exit if its not 64 bit OS
## http://technet.microsoft.com/en-us/library/dd903051.aspx
if("x64" >!< os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  uagName = registry_get_sz(key:key + item, item:"DisplayName");

  if(!uagName){
    continue;
  }

  if("Microsoft Forefront Unified Access Gateway" >< uagName)
  {
    uagVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(uagVer)
    {
      set_kb_item(name:"MS/Forefront/UAG/Ver", value:uagVer);
      cpe = build_cpe(value:uagVer, exp:"^([0-9.]+)",
                    base:"cpe:/a:microsoft:forefront_unified_access_gateway:");

      insPath= 'Could not determine InstallLocation from Registry\n';
      if(cpe)
        register_product(cpe:cpe, location:insPath);

      log_message(data:'Detected MS Forefront Unified Access Gateway version: ' + uagVer +
                      '\nLocation: ' + insPath +
                      '\nCPE: '+ cpe +
                      '\n\nConcluded from version identification result:\n' +
                      'MS ForefrontUnified Access Gateway ' + uagVer);

    }
  }
}
