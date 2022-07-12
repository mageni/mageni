###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_amarok_detect_lin.nasl 13935 2019-02-28 12:36:38Z cfischer $
#
# Amarok Player Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900430");
  script_version("$Revision: 13935 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 13:36:38 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Amarok Player Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the version of Amarok Player for Linux on
  remote host and sets the reuslt into KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

amarokPaths = find_file(file_name:"amarok", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);

foreach amarokBin (amarokPaths) {

  amarokBin = chomp(amarokBin);
  if(!amarokBin)
    continue;

  amarokVer = get_bin_version(full_prog_name:amarokBin, sock:sock, version_argv:"-v", ver_pattern:"Amarok: ([0-9]\.[0-9]+)");
  if(amarokVer[1]) {

    set_kb_item(name:"Amarok/Linux/Ver", value:amarokVer[1]);
    set_kb_item(name:"amarok/detected", value:TRUE);

    register_and_report_cpe(app:"Amarok Player", ver:amarokVer[1], base:"cpe:/a:amarok:amarok:", expr:"^([0-9.]+)", regPort:0, insloc:amarokBin, concluded:amarokVer[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);