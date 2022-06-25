###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magnicomp_sysinfo_detect_lin.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# MagniComp SysInfo Version Detection (Linux)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814303");
  script_version("$Revision: 13650 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-10-04 12:30:19 +0530 (Thu, 04 Oct 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MagniComp SysInfo Version Detection (Linux)");

  script_tag(name:"summary", value:"This script finds the installed version of
  MagniComp SysInfo on Linux.

  The script logs in via ssh, searches for binary file 'mcsysinfo' and queries
  the file for version");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_xref(name:"URL", value:"https://www.magnicomp.com");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

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

sysinfoName = find_bin(prog_name:"mcsysinfo", sock:sock);
foreach executableFile (sysinfoName)
{
  executableFile = chomp(executableFile);
  sysinfoVer = get_bin_version(full_prog_name:executableFile, version_argv:"-V", ver_pattern:"SysInfo Version ([0-9A-Z. )(]+)", sock:sock);
  if(sysinfoVer)
  {
    version = ereg_replace(pattern:"[()]", string:sysinfoVer[1], replace:"");
    set_kb_item(name:"Sysinfo/Linux/Ver", value:version);

    cpe = register_and_report_cpe(app:"MagniComp SysInfo", ver:version, base:"cpe:/a:magnicomp:sysinfo:",
                                  expr:"^([0-9A-Z. ]+)",insloc:executableFile);
    exit(0);
  }
}

ssh_close_connection();
exit(0);