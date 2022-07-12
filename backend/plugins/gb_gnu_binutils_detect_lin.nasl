###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnu_binutils_detect_lin.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# GNU Binutils Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806085");
  script_version("$Revision: 10906 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 15:03:47 +0530 (Tue, 13 Oct 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("GNU Binutils Version Detection (Linux)");

  script_tag(name:"summary", value:"This script finds the GNU Binutils
  installed version on Linux.

  The script logs in via ssh, execute the command 'dpkg' and get version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

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

res = ssh_cmd(socket:sock, cmd:'dpkg -l | grep "binutil"');

if('binutils' >!< res)
{
  ssh_close_connection();
  exit(0);
}

binVer = eregmatch(pattern:'([0-9.]+)', string:res);

if(binVer[0] != NULL)
{
  set_kb_item(name:"GNU/Binutils/Linux/Ver", value:binVer[0]);

  ## Builging cpe
  cpe = build_cpe(value:binVer[0], exp:"^([0-9.]+)", base:"cpe:/a:gnu:binutils:");
  if(isnull(cpe))
    cpe ="cpe:/a:gnu:binutils";

  register_product(cpe:cpe, location:"/");

  log_message(data: build_detection_report(app: "GNU Binutils", version:binVer[0],
                                         install: "/",
                                         cpe: cpe,
                                         concluded: binVer[0]));
}

ssh_close_connection();
