###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_sketchup_detect_macosx.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Google SketchUp Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902680");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 15:49:33 +0530 (Mon, 21 May 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google SketchUp Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of Google SketchUp.

The script logs in via ssh, searches for folder 'SketchUp.app' and
queries the related 'info.plist' file for string 'CFBundleVersion' via command
line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

foreach ver (make_list("5", "6", "7", "8"))
{
  gsVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Google\ SketchUp\ " + ver +"/SketchUp.app/" +
             "Contents/Info CFBundleVersion"));
  if(isnull(gsVer) || "does not exist" >< gsVer){
     continue;
  }

  set_kb_item(name: "Google/SketchUp/MacOSX/Version", value:gsVer);

  cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:google:sketchup:");
  if(isnull(cpe))
    cpe='cpe:/a:google:sketchup';

  path = '/Applications/Google SketchUp ' + ver + '/SketchUp.app/';

  register_product(cpe:cpe, location:path);

  log_message(data: build_detection_report(app: "Google SketchUp",
                                           version:gsVer,
                                           install:path,
                                           cpe:cpe,
                                           concluded: gsVer));
}
