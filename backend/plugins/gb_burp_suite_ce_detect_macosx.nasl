###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_burp_suite_ce_detect_macosx.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Burp Suite Community Edition Version Detection (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813610");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 16:38:09 +0530 (Tue, 19 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Burp Suite Community Edition Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Burp Suite Community Edition on MAC OS X.

  The script logs in via ssh, searches for folder
  'Burp Suite Community Edition Installer.app' and queries the related 'info.plist'
   file for string 'CFBundleShortVersionString' via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

burpVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                       "Burp\ Suite\ Community\ Edition\ Installer.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(burpVer) || "does not exist" >< burpVer){
  exit(0);
}

set_kb_item(name: "BurpSuite/CE/MacOSX/Version", value:burpVer);

## New cpe created
cpe = build_cpe(value:burpVer, exp:"^([0-9.]+)", base:"cpe:/a:portswigger:burp_suite:");
if(isnull(cpe))
  cpe = 'cpe:/a:portswigger:burp_suite';

register_product(cpe:cpe, location:'/Applications/Burp Suite Community Edition Installer.app');

log_message(data: build_detection_report(app: "Burp Suite Community Edition",
                                         version: burpVer,
                                         install: "/Applications/Burp Suite Community Edition Installer.app",
                                         cpe: cpe,
                                         concluded: burpVer));
exit(0);
