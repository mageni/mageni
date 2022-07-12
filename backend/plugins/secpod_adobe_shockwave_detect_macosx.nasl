###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# Adobe Shockwave Player Version Detection (MacOSX)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902619");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_name("Adobe Shockwave Player Version Detection (MacOSX)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Shockwave Player on Mac OS X.

  The script logs in via ssh, and searches for adobe products '.app' folder
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
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

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
          "Application\ Support/Adobe/Shockwave/DirectorShockwave.bundle/"+
          "Contents/Info CFBundleShortVersionString"));

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\ Support/Adobe/Shockwave\ "+ i +
               "/DirectorShockwave.bundle/Contents/Info " +
               "CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\ Support/Macromedia/Shockwave\ "+ i +
               "/Shockwave.bundle/Contents/Info CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

close(sock);

if(isnull(shockVer) || "does not exist" >< shockVer){
  exit(0);
}

shockVer = ereg_replace(pattern:"r", string:shockVer, replace: ".");

set_kb_item(name: "Adobe/Shockwave/MacOSX/Version", value:shockVer);

cpe = build_cpe(value: shockVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
if(isnull(cpe))
  cpe = "cpe:/a:adobe:shockwave_player";

register_product(cpe: cpe, location: "/Library/");

log_message(data: build_detection_report(app: "Adobe Shockwave Player",
                                         version: shockVer,
                                         install: "/Applications/",
                                         cpe: cpe,
                                         concluded: shockVer));
