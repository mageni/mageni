###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_indesign_server_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# Adobe InDesign Server Version Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810240");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 12:59:49 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("Adobe InDesign Server Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe InDesign Server on MAC OS X.

  The script logs in via ssh, searches for folder 'install.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

name = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "install.app/Contents/Info " +
            "CFBundleGetInfoString"));

if(name =~ "Copyright.*Adobe Systems")
{
  installVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "install.app/Contents/Info " +
              "CFBundleVersion"));
}
else
{
  installVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "Adobe\ InDesign\ CC\ 2018/Adobe\ InDesign\ CC\ 2018.app/Contents/Info " +
               "CFBundleShortVersionString"));
}
close(sock);

if(isnull(installVer) || "does not exist" >< installVer){
  exit(0);
}

set_kb_item(name: "InDesign/Server/MacOSX/Version", value:installVer);

## created new cpe
cpe = build_cpe(value:installVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_server:");
if(isnull(cpe))
  cpe='cpe:/a:adobe:indesign_server';

register_product(cpe:cpe, location:'/Applications');

log_message(data: build_detection_report(app: "Adobe Indesign Server",
                                           version: installVer,
                                           install: "/Applications",
                                           cpe: cpe,
                                           concluded: installVer));
exit(0);

