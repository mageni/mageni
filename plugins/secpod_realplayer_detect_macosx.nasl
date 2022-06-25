###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_detect_macosx.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# RealNetworks RealPlayer Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902622");
  script_version("$Revision: 11285 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("RealNetworks RealPlayer Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of RealPlayer on MAC.

The script logs in via ssh, gets the version by using a command and set
it in the KB item.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2011 SecPod");
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

if (!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

realVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "RealPlayer.app/Contents/Info CFBundleShortVersionString"));

fullVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "RealPlayer.app/Contents/Info HelixVersion"));

close(sock);

if(isnull(realVer) || "does not exist" >< realVer){
  exit(0);
}

set_kb_item(name: "RealPlayer/MacOSX/Version", value:realVer);
insloc = "Unable to find the install Location.";

if(fullVer)
{
  set_kb_item(name: "RealPlayer/MacOSX/FullVer", value:fullVer);
  register_and_report_cpe( app:"RealPlayer", ver:fullVer, concluded:fullVer, base:"cpe:/a:realnetworks:realplayer:", expr:"^([0-9.]+)", insloc:insloc );
  exit(0);
}

register_and_report_cpe( app:"RealPlayer", ver:realVer, concluded:realVer, base:"cpe:/a:realnetworks:realplayer:", expr:"^([0-9.]+)", insloc:insloc );