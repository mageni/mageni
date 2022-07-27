###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opensc_detect.nasl 13273 2019-01-24 15:12:48Z asteins $
#
# OpenSC Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800369");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13273 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 16:12:48 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenSC Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of OpenSC on the host.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if(openscName = find_file(file_name:"opensc-config", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock)) {
  foreach binName (openscName) {
    binName = chomp(binName);
    openscVer = get_bin_version(full_prog_name:binName, ver_pattern:"([0-9.]+)", version_argv:"--version", sock:sock);

    if(openscVer[0]) {
    	version = openscVer[1];
    	set_kb_item( name:"opensc/detected", value:TRUE );
    	set_kb_item( name:"opensc/ssh/detected", value:TRUE );
    	register_and_report_cpe( app:"OpenSC", ver:version, base:"cpe:/a:opensc-project:opensc:", expr:"([0-9.]+)", regPort:0, insloc:binName, concluded:openscVer[0], regService:"ssh-login" );

    }
  }
}

ssh_close_connection();
exit(0);
