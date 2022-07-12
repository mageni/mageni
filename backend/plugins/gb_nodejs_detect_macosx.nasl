###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nodejs_detect_macosx.nasl 12706 2018-12-07 14:02:55Z cfischer $
#
# Node.js Version Detection (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813474");
  script_version("$Revision: 12706 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 15:02:55 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-07-10 11:02:12 +0530 (Tue, 10 Jul 2018)");
  script_name("Node.js Version Detection (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of
  Node.js on MAC OS X.

  The script logs in via ssh, and gets the version via command line option
  'node -v'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"node", sock:sock);
foreach nodebin (paths)
{
  nodeVer = get_bin_version(full_prog_name:chomp(nodebin), sock:sock,
                             version_argv:"-v", ver_pattern:"v([0-9.]+)");
  if(nodeVer[1])
  {
    set_kb_item(name:"Nodejs/MacOSX/Installed", value:TRUE);
    set_kb_item(name:"Nodejs/MacOSX/Ver", value:nodeVer[1]);

    register_and_report_cpe(app:"Node.js", ver:nodeVer[1], base:"cpe:/a:nodejs:node.js:",
                            expr:"^([0-9.]+)", insloc:nodebin );
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
exit(0);