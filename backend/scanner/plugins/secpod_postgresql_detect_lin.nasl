###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postgresql_detect_lin.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# PostgreSQL Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
# Revised to comply with Change Request #57.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900478");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11279 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("PostgreSQL Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of PostgreSQL.

The script logs in via ssh, searches for executable 'psql' and
queries the found executables via command line option '--version'.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

postgresql = find_file(file_name:"psql", file_path:"/", useregex:TRUE,
                        regexpar:"$", sock:sock);
foreach executableFile (postgresql)
{
  executableFile = chomp(executableFile);
  postgresqlVer = get_bin_version(full_prog_name:executableFile, version_argv:"--version",
                                  ver_pattern:"psql \(PostgreSQL\) ([0-9.]+)", sock:sock);
  if(postgresqlVer[1] != NULL)
  {
    set_kb_item(name:"PostgreSQL/Lin/Ver", value:postgresqlVer[1]);
    cpe = build_cpe(value: postgresqlVer[1], exp:"^([0-9.]+)",base:"cpe:/a:postgresql:postgresql:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile);

    log_message(data:'Detected PostgreSQL version: ' + postgresqlVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + postgresqlVer[max_index(postgresqlVer)-1]);
  }
}

ssh_close_connection();
