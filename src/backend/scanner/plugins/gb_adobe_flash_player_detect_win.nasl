###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_detect_win.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800029");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Flash Player/Flash CS/AIR/Flex
  on Windows.

  The script logs in via smb, searches for Adobe Products in the registry
  and gets the version from 'DisplayVersion' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

# nb: To make openvas-nasl-lint happy...
checkduplicate = "";
checkduplicate_path = "";
airFlag = 0;
csFlag = 0;
playerFlag = 0;
flexFlag = 0;

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    adobeName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Adobe AIR" >< adobeName && airFlag == 0)
    {
      airVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(airVer != NULL)
      {

        if (airVer + ", " >< checkduplicate && insPath + ", " >< checkduplicate_path){
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += airVer + ", ";
        checkduplicate_path += insPath + ", ";

        set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);
        set_kb_item(name:"Adobe/Air/Win/Installed", value:TRUE);

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Adobe/Air64/Win/Ver", value:airVer);
          register_and_report_cpe( app:adobeName, ver:airVer, base:"cpe:/a:adobe:adobe_air:x64:", expr:"^([0-9.]+)", insloc:insPath );
        } else {
          set_kb_item(name:"Adobe/Air/Win/Ver", value:airVer);
          register_and_report_cpe( app:adobeName, ver:airVer, base:"cpe:/a:adobe:adobe_air:", expr:"^([0-9.]+)", insloc:insPath );
        }
      }
    }

    else if("Adobe Flash CS" >< adobeName && csFlag == 0)
    {
      fcsVer = eregmatch(pattern:"Flash (CS[0-9])", string:adobeName);
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(fcsVer[1] != NULL)
      {
        set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Adobe/FlashCS64/Win/Ver", value:fcsVer[1]);
          register_and_report_cpe( app:adobeName, ver:fcsVer[1], base:"cpe:/a:adobe:flash_cs:x64:", expr:"^([0-9.]+)", insloc:insPath );
        } else {
          set_kb_item(name:"Adobe/FlashCS/Win/Ver", value:fcsVer[1]);
          register_and_report_cpe( app:adobeName, ver:fcsVer[1], base:"cpe:/a:adobe:flash_cs:", expr:"^([0-9.]+)", insloc:insPath );
        }
      }
    }

    else if("Adobe Flash Player" >< adobeName && playerFlag == 0)
    {
      playerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(!insPath){
        insPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      }

      if(!insPath){
        insPath = "Could not find the install location from registry";
      }

      if(playerVer != NULL)
      {
        set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);
        set_kb_item(name:"AdobeFlashPlayer/Win/Installed", value:TRUE);
        set_kb_item(name:"AdobeFlashPlayer/Win/Ver", value:playerVer);
        register_and_report_cpe( app:adobeName, ver:playerVer, base:"cpe:/a:adobe:flash_player:", expr:"^([0-9.]+)", insloc:insPath );

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"AdobeFlashPlayer64/Win/Ver", value:playerVer);
          register_and_report_cpe( app:adobeName, ver:playerVer, base:"cpe:/a:adobe:flash_player:x64:", expr:"^([0-9.]+)", insloc:insPath );
        }

        ## Commented as we need to find multiple adobe versions for
        ## IE and other browsers
        #playerFlag = 1;
      }
    }

    else if("Adobe Flex" >< adobeName && flexFlag == 0)
    {
      flexVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(flexVer != NULL)
      {

        set_kb_item(name:"Adobe/Flex/Win/Installed", value:TRUE);

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Adobe/Flex64/Win/Ver", value:flexVer);
          register_and_report_cpe( app:adobeName, ver:flexVer, base:"cpe:/a:adobe:flex:x64:", expr:"^([0-9.]+)", insloc:insPath );
        } else {
          set_kb_item(name:"Adobe/Flex/Win/Ver", value:flexVer);
          register_and_report_cpe( app:adobeName, ver:flexVer, base:"cpe:/a:adobe:flex:", expr:"^([0-9.]+)", insloc:insPath );
        }
      }
    }
  }
}
