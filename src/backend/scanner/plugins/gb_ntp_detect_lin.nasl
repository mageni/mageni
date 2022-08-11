###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_detect_lin.nasl 13936 2019-02-28 12:54:19Z cfischer $
#
# NTP Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800407");
  script_version("$Revision: 13936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 13:54:19 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NTP Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ntp_open.nasl", "gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the installed version of NTPd and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "NTP Version Detection (Linux)";

ntpVersion = get_kb_item("NTP/Linux/Ver");
if(!ntpVersion)
{
  sock = ssh_login_or_reuse_connection();
  if( ! sock ) exit( 0 );

  binFiles = find_file(file_name:"ntpd",file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
  foreach binName (binFiles) {

    binName = chomp(binName);
    if(!binName)
      continue;

    ntpVer = get_bin_version(full_prog_name:binName, sock:sock, version_argv:"--version", ver_pattern:"ntpd.* ([0-9]\.[0-9.]+)([a-z][0-9]+)?-?(RC[0-9])?");
    if(ntpVer[1]) {

      vers = eregmatch(string:ntpVer[0], pattern:"ntpd.* ([0-9]\.[0-9.]+)([a-z][0-9]+)?-?(RC[0-9])?");
      if(vers[2] =~ "[a-z][0-9]+" && vers[3] =~ "RC") {
        version = vers[1] + vers[2] + "." + vers[3];
      } else if(vers[2] =~ "[a-z][0-9]+") {
        version = vers[1] + vers[2];
      } else {
        version = vers[1];
      }

      set_kb_item(name:"NTP/Linux/Ver", value:version);
      set_kb_item(name:"ntpd/detected", value:TRUE);

      register_and_report_cpe(app:"NTP", ver:version, base:"cpe:/a:ntp:ntp:", expr:"^([0-9.]+[a-z0-9]*)", regPort:0, insloc:binName, concluded:ntpVer[0], regService:"ssh-login" );
    }
  }
  ssh_close_connection();
}

exit( 0 );