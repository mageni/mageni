###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visual Studio Team Foundation Server Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802961");
  script_version("2019-04-12T12:30:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-12 12:30:40 +0000 (Fri, 12 Apr 2019)");
  script_tag(name:"creation_date", value:"2012-09-12 11:27:31 +0530 (Wed, 12 Sep 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Visual Studio Team Foundation Server Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Visual Studio
  Team Foundation Server.

  The script logs in via smb, searches for Microsoft Visual Studio Team
  Foundation Server in the registry and gets the version from 'DisplayVersion'
  string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

mstfkey = "SOFTWARE\Microsoft\TeamFoundationServer\";

if(!registry_key_exists(key:mstfkey)){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  tfName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft Team Foundation Server" >< tfName )
  {
    tfNum = eregmatch(pattern:"[0-9.]+ (Update [0-9.]+)?", string:tfName);
    tfVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(tfVer)
    {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath)
      {
        if (tfVer =~ "^12\."){
          insPath = registry_get_sz(key:mstfkey+ "12.0", item:"InstallPath");
        }

        else if (tfVer =~ "^14\."){
          insPath = registry_get_sz(key:mstfkey+ "14.0", item:"InstallPath");
        }

        else if (tfVer =~ "^15\."){
          insPath = registry_get_sz(key:mstfkey+ "15.0", item:"InstallPath");
        }

        else if (tfVer =~ "^16\."){
          insPath = registry_get_sz(key:mstfkey+ "16.0", item:"InstallPath");
        }

        if(!insPath){
          insPath = "Could not find the install location from registry";
        }
      }

      set_kb_item(name:"MS/VS/Team/Foundation/Server/Ver", value:tfVer);
      set_kb_item(name:"MS/VS/Team/Foundation/Server/Path", value:insPath);

      if(tfNum[0])
      {
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:visual_studio_team_foundation_server:"
                                 + tfNum[0]);
      }
      else{
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:visual_studio_team_foundation_server:"+ tfVer);
      }

      if(!cpe){
        cpe = "cpe:/a:microsoft:visual_studio_team_foundation_server";
      }

      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app:"MS VS Team Foundation",
                                              version:tfVer, install:insPath, cpe:cpe,
                                              concluded: tfVer));
    }
  }

  ## For latest TFS == AzureDevOps Server 2019
  if("AzureDevOpsCore2019" >< tfName )
  {
    tfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(tfVer)
    {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath)
      {
        if (tfVer =~ "^17\."){
          insPath = registry_get_sz(key:mstfkey+ "17.0", item:"InstallPath");
          if(!insPath){
            insPath = "Could not find the install location from registry";
          }
        }
      }
      set_kb_item(name:"MS/Azure/DevOps/Server/Ver", value:tfVer);
      set_kb_item(name:"MS/Azure/DevOps/Server/Path", value:insPath);

      cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)",
                      base:"cpe:/a:microsoft:azure_devops_server:"+ tfVer);
      if(!cpe){
        cpe = "cpe:/a:microsoft:azure_devops_server";
      }

      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app:"MS Azure DevOps Server",
                                              version:tfVer, install:insPath, cpe:cpe,
                                              concluded: tfVer));
      exit(0);
    }
  }
}
