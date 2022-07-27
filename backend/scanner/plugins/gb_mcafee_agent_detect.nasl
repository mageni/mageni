###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_agent_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# McAfee Agent Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805293");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-02 14:04:22 +0530 (Mon, 02 Mar 2015)");
  script_name("McAfee Agent Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  McAfee Agent.

  The script logs in via smb, searches for string 'McAfee' in the registry
  and reads the version information from registry.");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    agentName = registry_get_sz(key:key + item, item:"DisplayName");

    if("McAfee Agent" >< agentName)
    {
      agentVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      agentPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(!agentPath){
        agentPath = "Couldn find the install location from registry";
      }
      if(agentVer)
      {
        set_kb_item(name:"McAfee/Agent/Win/Ver", value:agentVer);

        cpe = build_cpe(value:agentVer, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:mcafee_agent:");
        if(isnull(cpe))
          cpe = "cpe:/a:mcafee:mcafee_agent";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"McAfee/Agent64/Win/Ver", value:agentVer);
          cpe = build_cpe(value:agentVer, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:mcafee_agent:x64:");
          if(isnull(cpe)){
           cpe = "cpe:/a:mcafee:mcafee_agent:x64";
          }
        }

        register_product(cpe:cpe, location:agentPath);

        log_message(data: build_detection_report(app: "McAfee Agent",
                                             version: agentVer,
                                             install: agentPath,
                                             cpe: cpe,
                                             concluded: agentVer));
        exit(0);
      }
    }
  }
}
