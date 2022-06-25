###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_detect_macosx.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# VLC Media Player Version Detection (MacOSX)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802724");
  script_version("$Revision: 11285 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-22 15:56:23 +0530 (Thu, 22 Mar 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player Version Detection (MacOSX)");

  script_tag(name:"summary", value:"Detects the installed version of VLC
  Media Player.

  This script logs in via ssh, searches for folder 'VLC.app' and queries the
  related 'info.plist' file for string 'CFBundleShortVersionString' via command
  line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

vlcVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                          "VLC.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(!vlcVer || "does not exist" >< vlcVer){
  exit(0);
}

cpe = build_cpe(value:vlcVer, exp:"^([0-9.]+)", base:"cpe:/a:videolan:vlc_media_player:");
if(isnull(cpe))
  cpe = "cpe:/a:videolan:vlc_media_player";

register_product(cpe:cpe, location:'/Applications/VLC.app');

set_kb_item(name: "VLC/Media/Player/MacOSX/Version", value:vlcVer);

log_message(data: build_detection_report(app: "VLC Media Player",
                                           version: vlcVer,
                                           install: "/Applications/VLC.app",
                                           cpe: cpe,
                                           concluded: vlcVer));
