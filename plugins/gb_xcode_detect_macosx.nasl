###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xcode_detect_macosx.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Xcode Version Detection (Mac OS X)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811965");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-11-03 11:30:51 +0530 (Fri, 03 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Xcode Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Xcode on MAC OS X.

  The script logs in via ssh, searches for folder 'Xcode.app' and queries
  the related 'info.plist' file for string 'CFBundleShortVersionString' via
  command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

xcVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Xcode.app/Contents/Info " +
            "CFBundleShortVersionString"));

close(sock);

if(isnull(xcVer) || "does not exist" >< xcVer){
  exit(0);
}

set_kb_item(name: "Xcode/MacOSX/Version", value:xcVer);

cpe = build_cpe(value:xcVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:xcode:");
if(isnull(cpe))
  cpe='cpe:/a:apple:xcode';

register_product(cpe:cpe, location:'/Applications/Xcode.app');

log_message(data: build_detection_report(app: "Apple Xcode",
                                         version: xcVer,
                                         install: "/Applications/Xcode.app/",
                                         cpe: cpe,
                                         concluded: xcVer));
exit(0);
