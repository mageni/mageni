###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flash_player_within_google_chrome_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# Adobe Flash Player Within Google Chrome Detection (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810614");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 15:08:22 +0530 (Tue, 14 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Flash Player Within Google Chrome Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Flash within google chrome.

  The script logs in via ssh and extracts the version from the binary file
  'libpepflashplayer.so'.");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

flashIns = ssh_cmd(socket:sock, cmd:"ls ~/Library/" +
          "Application\ Support/Google/Chrome/PepperFlash");

##A list of directories will be output with flash version as directory names
versions = str_replace(find:'\n', replace:" ",string:flashIns);
versionList =  split(versions, sep:' ', keep:FALSE);

##NOTE:: When New Flash Plugin is updated on installed
##a new directory is created. Always there are directories
##of old and latest Flash plugin here. Checking for
##latest version directory only
##Lets figure out largest version present
maxVer = versionList[1];
foreach version (versionList)
{
  if((version =~ "^[0-9]+") && (maxVer < version)){
    maxVer = version;
  } else {
    continue;
  }
}


flashVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read ~/Library/" +
               "Application\ Support/Google/Chrome/PepperFlash/" +
               maxVer + "/PepperFlashPlayer.plugin/Contents/Info.plist " +
               "CFBundleVersion"));

if(isnull(flashVer) || "does not exist" >< flashVer){
  exit(0);
}

set_kb_item(name: "AdobeFlashPlayer/Chrome/MacOSX/Ver", value:flashVer);

cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player_chrome:");
if(isnull(cpe))
  cpe = "cpe:/a:adobe:flash_player_chrome";

register_product(cpe:cpe, location:"/Applications/");
log_message(data: build_detection_report(app: "Flash Player Within Google Chrome",
                                               version: flashVer,
                                               install: "/Applications/",
                                               cpe: cpe,
                                               concluded: flashVer));
exit(0);
