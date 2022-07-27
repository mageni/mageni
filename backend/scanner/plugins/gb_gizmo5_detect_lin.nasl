###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gizmo5_detect_lin.nasl 12733 2018-12-10 09:17:04Z cfischer $
#
# Gizmo5 Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800832");
  script_version("$Revision: 12733 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 10:17:04 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gizmo5 Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script is detects the installed version of Gizmo5.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

gizmo_sock = ssh_login_or_reuse_connection();
if(!gizmo_sock){
  exit(0);
}

garg[0] = "-o";
garg[1] = "-m2";
garg[2] = "-a";
garg[3] = string("[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+");

gizmoName = find_bin(prog_name:"gizmo", sock:gizmo_sock);
if(!gizmoName){
  ssh_close_connection();
  exit(0);
}

foreach binaryName(gizmoName) {

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " "+garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  gizmoVer = get_bin_version(full_prog_name:"grep", version_argv:arg, sock:gizmo_sock, ver_pattern:"([0-9]\.[0-9]\.[0-9]\.[0-9][0-9]?)");
  if(gizmoVer[1]){

    set_kb_item(name:"Gizmo5/Linux/Ver", value:gizmoVer[1]);
    register_and_report_cpe(app:"Gizmo5", ver:gizmoVer[1], base:"cpe:/a:gizmo5:gizmo:", expr:"([0-9.]+)", regPort:0, insloc:binaryName, concluded:gizmoVer[0], regService:"ssh-login");
    break;
  }
}

ssh_close_connection();
exit(0);