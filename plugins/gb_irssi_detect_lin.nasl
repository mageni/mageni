###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irssi_detect_lin.nasl 13040 2019-01-11 14:10:45Z asteins $
#
# Irssi Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800633");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13040 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-11 15:10:45 +0100 (Fri, 11 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Irssi Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Irssi.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

irrsi_sock = ssh_login_or_reuse_connection();
if(!irrsi_sock) {
  exit(0);
}

paths = find_bin(prog_name:"irssi", sock:irrsi_sock);

foreach irssi_bin (paths) {
  irssi_ver = get_bin_version(full_prog_name:chomp(irssi_bin), sock:irrsi_sock, version_argv:"--version", ver_pattern:"irssi ([0-9.]+)");

  if(irssi_ver[1]) {
    vers = irssi_ver[1];
    set_kb_item(name:"irssi/detected", value:TRUE);
    set_kb_item(name:"Irssi/Lin/Ver", value:vers);

    register_and_report_cpe( app:"irssi", ver:vers, base:"cpe:/a:irssi:irssi:", expr:"([0-9.]+)", regPort:0, insloc:irssi_bin, concluded:irssi_ver[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);
