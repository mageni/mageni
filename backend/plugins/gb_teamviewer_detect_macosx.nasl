###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_detect_macosx.nasl 11476 2018-09-19 12:16:07Z cfischer $
#
# TeamViewer Version Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813896");
  script_version("$Revision: 11476 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 14:16:07 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-07 13:42:31 +0530 (Fri, 07 Sep 2018)");
  script_name("TeamViewer Version Detection (Mac OS X)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  script_xref(name:"URL", value:"https://www.teamviewer.com/en");

  script_tag(name:"summary", value:"Detects the installed version of
  TeamViewer on MAC OS X.

  The script logs in via ssh, searches for folder 'TeamViewer.app' and queries the
  related 'info.plist' file for string 'CFBundleShortVersionString' via command line
  option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

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

teamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                         "TeamViewer.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(teamVer) || "does not exist" >< teamVer){
  exit(0);
}

set_kb_item(name:"TeamViewer/MacOSX/Version", value:teamVer);

cpe = build_cpe(value:teamVer, exp:"^([0-9.]+)", base:"cpe:/a:teamviewer:teamviewer:");
if(isnull(cpe))
  cpe = 'cpe:/a:teamviewer:teamviewer';

register_product(cpe:cpe, location:'/Applications/TeamViewer.app');

log_message(data:build_detection_report(app:"TeamViewer",
                                        version:teamVer,
                                        install:"/Applications/TeamViewer.app",
                                        cpe:cpe,
                                        concluded:teamVer));
exit(0);
