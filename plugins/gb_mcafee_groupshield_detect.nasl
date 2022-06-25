###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_groupshield_detect.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# McAfee GroupShield Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800618");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-22 10:20:17 +0200 (Fri, 22 May 2009)");
  script_name("McAfee GroupShield Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of McAfee GroupShield on Windows.

The script logs in via smb, searches for McAfee GroupShield in the registry
and gets the version from registry.");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach groupshieldKey (key_list)
{
  foreach item(registry_enum_keys(key:groupshieldKey))
  {
    groupName = registry_get_sz(key:groupshieldKey + item, item:"DisplayName");

    if("McAfee GroupShield" >< groupName && "Exchange" >< groupName)
    {
      groupshieldVer = registry_get_sz(key:groupshieldKey + item, item:"DisplayVersion");

      groupshieldPath = registry_get_sz(key:groupshieldKey + item, item:"InstallLocation");
      if(!groupshieldPath){
        groupshieldPath = "Couldn find the install location from registry";
      }

      if(groupshieldVer != NULL) {

        set_kb_item(name:"McAfee/GroupShield/Exchange/Installed", value:TRUE);

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< groupshieldKey) {
          set_kb_item(name:"McAfee/GroupShield64/Exchange/Ver", value:groupshieldVer);
          register_and_report_cpe( app:"McAfee GroupShield", ver:groupshieldVer, base:"cpe:/a:mcafee:groupshield:x64:", expr:"^([0-9.]+)", insloc:groupshieldPath );
        } else {
          set_kb_item(name:"McAfee/GroupShield/Exchange/Ver", value:groupshieldVer);
          register_and_report_cpe( app:"McAfee GroupShield", ver:groupshieldVer, base:"cpe:/a:mcafee:groupshield:", expr:"^([0-9.]+)", insloc:groupshieldPath );
        }
      }
    }
  }
}
