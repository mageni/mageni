###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_detect_macosx.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Python Version Detection (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804633");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-06-09 16:03:10 +0530 (Mon, 09 Jun 2014)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Python Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of python on Mac OS X.

The script logs in via ssh, searches for folder 'Python' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

pythonSeries = make_list("2.5", "2.6", "2.7", "3.1", "3.2", "3.3", "3.4");

foreach series(pythonSeries)
{
  pythonVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Python\ " +
   series + "/Python\ Launcher.app/Contents/Info.plist CFBundleShortVersionString"));

  if((!pythonVer) || "does not exist" >< pythonVer){
    continue;
  }

  set_kb_item(name: "python/MacOSX/Version", value:"pythonVer");

  cpe = build_cpe(value:pythonVer, exp:"^([0-9.]+)", base:"cpe:/a:python:python:");
  if(isnull(cpe))
    cpe = "cpe:/a:python:python";

  appPath = '/Applications/Python' + series + "/Python Launcher.app";
  register_product(cpe:cpe, location: appPath);

  log_message(data: build_detection_report(app: "Python",
                                           version: pythonVer,
                                           install: appPath,
                                           cpe: cpe,
                                           concluded: pythonVer));
}

close(sock);
