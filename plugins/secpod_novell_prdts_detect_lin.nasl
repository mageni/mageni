##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_prdts_detect_lin.nasl 12741 2018-12-10 12:18:00Z cfischer $
#
# Novell Products Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900598");
  script_version("$Revision: 12741 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 13:18:00 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Novell Products Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves the installed
  version of Novell products and saves the result in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc"); # For make_list_unique

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

eDirPath = find_bin(prog_name:"ndsd", sock:sock);
if(eDirPath) {

  edirPath = make_list_unique(edirPath, "/opt/novell/eDirectory/sbin/ndsd");

  foreach eDirFile(eDirPath) {

    eDirFile = chomp(eDirFile);
    if(!eDirFile) continue;

    eDirVer = get_bin_version(full_prog_name:eDirFile, version_argv:"--version", ver_pattern:"Novell eDirectory ([0-9.]+).?(SP[0-9]+)?", sock:sock);
    if(eDirVer[1]) {
      if(eDirVer[2]) {
        version = eDirVer[1] + "." + eDirVer[2];
      } else {
        version = eDirVer[1];
      }
      set_kb_item(name:"Novell/eDir/Lin/Ver", value:version);
      register_and_report_cpe(app:"Novell eDirectory version", ver:version, base:"cpe:/a:novell:edirectory:", expr:"^([0-9.]+([a-z0-9]+)?)", insloc:eDirFile, regService:"ssh-login", regPort:0, concluded:eDirVer[0]);
    }
  }
}

iPrintPaths = find_file(file_name:"iprntcmd", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!iPrintPaths){
  ssh_close_connection();
  exit(0);
}

foreach iPrintBin(iPrintPaths) {

  iPrintBin = chomp(iPrintBin);
  if(!iPrintBin) continue;

  iPrintVer = get_bin_version(full_prog_name:iPrintBin, sock:sock, version_argv:"-v", ver_pattern:" v([0-9.]+)");
  if(iPrintVer[1]) {

    set_kb_item(name:"Novell/iPrint/Client/Linux/Ver", value:iPrintVer[1]);
    register_and_report_cpe(app:"Novell iPrint Client", ver:iPrintVer[1], base:"cpe:/a:novell:iprint_client:", expr:"^([0-9]\.[0-9]+)", insloc:iPrintBin, regService:"ssh-login", regPort:0, concluded:iPrintVer[0]);
  }
}

ssh_close_connection();
exit(0);