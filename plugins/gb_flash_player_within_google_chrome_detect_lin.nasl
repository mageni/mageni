###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flash_player_within_google_chrome_detect_lin.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# Adobe Flash Player Within Google Chrome Detection (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810613");
  script_version("$Revision: 10883 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 13:47:05 +0530 (Mon, 13 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Flash Player Within Google Chrome Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Flash within google chrome.

  The script logs in via ssh and extracts the version from the binary file
  'libpepflashplayer.so'.");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

flash_sock = ssh_login_or_reuse_connection();
if(!flash_sock){
  exit(0);
}

# nb: To make openvas-nasl-lint happy
checkduplicate = "";
checkduplicate_path = "";

flashName = find_file(file_name:"libpepflashplayer.so", file_path:"/",
                      useregex:TRUE, regexpar:"$", sock:flash_sock);
if(flashName != NULL)
{
  for(a = 0; a < max_index(flashName); a++)
  {
    if(flashName[a] =~ "google-chrome.*([0-9.]+)")
    {
      version =  eregmatch(pattern:"(.*google-chrome.*\/([0-9.]+))\/libpepflashplayer", string:flashName[a]);
      if(version[1] && version[2])
      {
        flashVer = version[2];
        insPath = version[1];
      }

      if (flashVer + ", " >< checkduplicate && insPath + ", " >< checkduplicate_path){
        continue;
      }
      ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate  += flashVer + ", ";
      checkduplicate_path += insPath + ", ";

      set_kb_item(name:"AdobeFlashPlayer/Chrome/Lin/Ver", value:flashVer);

      cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player_chrome:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:flash_player_chrome";

      register_product(cpe:cpe, location:insPath);
      log_message(data: build_detection_report(app: "Flash Player Within Google Chrome",
                                               version: flashVer,
                                               install: insPath,
                                               cpe: cpe,
                                               concluded: flashVer));

    }
  }
}
exit(0);
