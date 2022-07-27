###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freerdp_detect_lin.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# FreeRDP Version Detection (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809737");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 17:27:04 +0530 (Thu, 01 Dec 2016)");
  script_name("FreeRDP Version Detection (Linux)");
  script_tag(name:"summary", value:"Detects the installed version of
  FreeRDP.

  The script logs in via ssh, searches for executable 'xfreerdp' and
  queries the found executables via command line option '--version'.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

binFiles = find_file(file_name:"xfreerdp",file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);

foreach executableFile (binFiles)
{
  executableFile = chomp(executableFile);
  ftVer = get_bin_version(full_prog_name:executableFile, sock:sock,
                  version_argv:"--version",
                  ver_pattern:"([0-9.]+(-[A-Za-z0-9+]+)?)");

  if(ftVer[1] != NULL)
  {
    set_kb_item(name:"FreeRDP/Linux/Ver", value:ftVer[1]);
    cpe = build_cpe(value:ftVer[1], exp:"^([0-9.]+-?[A-Za-z0-9]+?[+]?[0-9]+?)", base:"cpe:/a:freerdp_project:freerdp:");
    if(!cpe)
      cpe = "cpe:/a:freerdp_project:freerdp";

    register_product(cpe:cpe, location:executableFile);

    log_message(data: build_detection_report(app:"FreeRDP",
                                           version: ftVer[1],
                                           install: executableFile,
                                           cpe: cpe,
                                           concluded: ftVer[1]));
    exit(0);
    close(sock);
  }
}
close(sock);
