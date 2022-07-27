###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iwork_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# iWork Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802145");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11283 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("iWork Version Detection (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  script_tag(name:"summary", value:"This script finds the installed product version of iWork and sets
  the result in KB");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

## For iWork, version is taken from any of its 3 components Keynote, Pages
## and Numbers. Taking version from Keynote Component
## Refer below wiki link for version mapping
## http://en.wikipedia.org/wiki/IWork

foreach ver (make_list("09","08", "07","06"))
{
  iworkVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "iWork\ \'"+ ver +"/Keynote.app/Contents/Info " +
                 "CFBundleShortVersionString"));

  if("does not exist" >!< iworkVer){
    break;
  }
}

close(sock);

if(isnull(iworkVer) || "does not exist" >< iworkVer){
  exit(0);
}

set_kb_item(name: "Apple/iWork/Keynote/MacOSX/Version", value:iworkVer);
log_message(data:"Apple iWork keynote version " + iworkVer +
                  " was detected on this host");
