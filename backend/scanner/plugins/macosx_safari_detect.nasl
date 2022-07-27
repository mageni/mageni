###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_safari_detect.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# Apple Safari Detect Script (Mac OS X)
#
# LSS-NVT-2010-009
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102021");
  script_version("$Revision: 11285 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Safari Detect Script (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of Apple Safari on Mac OS X.

The script logs in via ssh, searches for folder 'Safari.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
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

ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Safari.app/Contents/Info CFBundleShortVersionString"));

if(isnull(ver) || "does not exist" >< ver){
  log_message(data:"exiting" +ver);
  exit(0);
}
set_kb_item(name: "AppleSafari/MacOSX/Version", value:ver);

cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:apple:safari:");
if(isnull(cpe))
  cpe='cpe:/a:apple:safari';

register_product(cpe:cpe, location:'/Applications/Safari.app');

log_message(data: build_detection_report(app: "Safari", version: ver,
                                         install: "/Applications/Safari.app",
                                         cpe: cpe,
                                         concluded: ver));
