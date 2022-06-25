###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_detect_macosx.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# Adobe Products Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902711");
  script_version("$Revision: 11285 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Products Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Products.

  The script logs in via ssh, and searches for adobe products '.app' folder
  and queries the related 'info.plist' file for string 'CFBundleVersion'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}


########################################
##
## Get the version of Adobe Flash Player
##
########################################
buffer = get_kb_item("ssh/login/osx_pkgs");
if(buffer != NULL)
{
  if("com.adobe.pkg.FlashPlayer" >< buffer){
    flashVer = eregmatch(pattern:"FlashPlayer[^\n]([0-9.]+)", string:buffer);
  } else
  {
    version = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Internet\ Plug-Ins/Flash\ Player.plugin/Contents/Info.plist"));
    if(isnull(version) || "does not exist" >< version){
      exit(0);
    }
    flashVer = eregmatch(pattern:'CFBundleVersion = "([0-9.]+)"', string:version);
    if(!flashVer[1]){
      exit(0);
    }
  }

  if(flashVer[1] != NULL)
  {
    set_kb_item(name: "Adobe/Flash/Player/MacOSX/Version", value:flashVer[1]);
    set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
    register_and_report_cpe( app:"Adobe Flash Player", ver:flashVer[1], base:"cpe:/a:adobe:flash_player:", expr:"^([0-9.]+)", insloc:"/Applications/Install Adobe Flash Player.app" );
  }
}

####################################
##
## Check for shockwave player
##
####################################
if("com.adobe.shockwave" >< buffer)
{
  version = eregmatch(pattern:"shockwave[^\n]([0-9.]+)", string:buffer);
  if(version[1] != NULL)
  {
    set_kb_item(name: "Adobe/Shockwave/Player/MacOSX/Version", value:version[1]);
    set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
    register_and_report_cpe( app:"Adobe Shockwave Player", ver:version[1], base:"cpe:/a:adobe:shockwave_player:", expr:"^([0-9.]+)", insloc:"/Applications" );
  }
}


####################################
##
## Get the version of Adobe Air
##
####################################
airVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
         "Adobe\ AIR\ Installer.app/Contents/Info " +
         "CFBundleShortVersionString"));

if(!isnull(airVer) && "does not exist" >< airVer){
 airVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/Frameworks/" +
                        "Adobe\ AIR.framework/Versions/Current/Resources/" +
                        "Info.plist " + "CFBundleVersion"));


}

if(!isnull(airVer) && "does not exist" >!< airVer)
{
  set_kb_item(name: "Adobe/Air/MacOSX/Version", value:airVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe( app:"Adobe Air", ver:airVer, base:"cpe:/a:adobe:adobe_air:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe AIR Installer.app" );
}

####################################
##
## Get the version of Adobe Reader
##
####################################
readerVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Adobe\ Reader.app/Contents/Info CFBundleShortVersionString"));

app = "Adobe Reader";
if(isnull(readerVer) || "does not exist" >< readerVer)
{
  readerVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "Adobe\ Acrobat\ Reader\ 2017.app/Contents/Info CFBundleShortVersionString"));
  app = "Adobe Reader 2017";
}

if(!isnull(readerVer) && "does not exist" >!< readerVer)
{
  set_kb_item(name: "Adobe/Reader/MacOSX/Version", value:readerVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe( app:app, ver:readerVer, base:"cpe:/a:adobe:acrobat_reader:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe Reader.app" );
}


####################################
##
## Get the version of Adobe Acrobat
##
####################################
foreach ver (make_list("2017", "XI", "X", "10", "9", "8"))
{
  if(ver == "2017"){
    acrobatVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Adobe\ Acrobat\ 2017/Adobe\ Acrobat.app/Contents/Info CFBundleShortVersionString"));
  } else {

    acrobatVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Adobe\ Acrobat\ " + ver + "\ Pro/Adobe\ Acrobat\ Pro.app/" +
                 "Contents/Info CFBundleShortVersionString"));
  }

  if("does not exist" >!< acrobatVer){
       break;
  }
}

if(!isnull(acrobatVer) && "does not exist" >!< acrobatVer)
{
  set_kb_item(name: "Adobe/Acrobat/MacOSX/Version", value:acrobatVer);
  set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/MacOSX/Installed", value:TRUE);
  register_and_report_cpe( app:"Adobe Acrobat " + ver, ver:acrobatVer, base:"cpe:/a:adobe:acrobat:", expr:"^([0-9.]+)", insloc:"/Applications/Adobe Acrobat" );
}

close(sock);
