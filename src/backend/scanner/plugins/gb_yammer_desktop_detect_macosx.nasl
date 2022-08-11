###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yammer_desktop_detect_macosx.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# Yammer Desktop Version Detection (Mac OS X)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814325");
  script_version("$Revision: 13650 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-22 11:38:37 +0530 (Thu, 22 Nov 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Yammer Desktop Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of Yammer Desktop
  on Mac OS X.

  The script logs in via ssh, searches for folder 'Yammer.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

yamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                      "Yammer.app/Contents/Info CFBundleShortVersionString"));

close(sock);
if(isnull(yamVer) || "does not exist" >< yamVer){
  exit(0);
}

set_kb_item(name:"Microsoft/Yammer/Macosx/Ver", value:yamVer);
cpe = build_cpe(value:yamVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:yammer:");
if(isnull(cpe)){
  cpe = "cpe:/a:microsoft:yammer";
}

register_product(cpe: cpe, location:'/Applications/Yammer.app', service:"ssh-login", port:0);

report =  build_detection_report(app: "Microsoft Yammer",
                                 version: yamVer,
                                 install: "/Applications/Yammer.app",
                                 cpe: cpe,
                                 concluded: yamVer);
if(report){
  log_message( port:0, data:report );
}

exit(0);