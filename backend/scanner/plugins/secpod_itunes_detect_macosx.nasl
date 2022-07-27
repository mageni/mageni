###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# Apple iTunes Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902717");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_name("Apple iTunes Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"This script finds the installed product version of Apple iTunes
on Mac OS X and sets the result in KB");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
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

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

itunesVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                  "iTunes.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(itunesVer) || "does not exist" >< itunesVer){
  exit(0);
}

set_kb_item(name: "Apple/iTunes/MacOSX/Version", value:itunesVer);


cpe = build_cpe(value:itunesVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:itunes:");
if(isnull(cpe))
  cpe = 'cpe:/a:apple:itunes';

insPath = "/Applications/iTunes.app";

register_product(cpe:cpe, location:insPath);

log_message(data: build_detection_report(app: "Apple iTunes",
                                         version: itunesVer,
                                         install: insPath,
                                         cpe: cpe,
                                         concluded: itunesVer));
