###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_detect_lin.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# TeamViewer Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813269");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-07-30 16:57:40 +0530 (Mon, 30 Jul 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("TeamViewer Version Detection (Linux)");
  script_tag(name:"summary", value:"Detects the installed version of TeamViewer.

  The script logs in via SSH, searches for the executable 'TeamViewer.' and
  queries the found executables via the command line option '--version'");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://www.teamviewer.com/en");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
if( ! sock ) exit( 0 );

binaries = find_file( file_name:"teamviewer", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock );
foreach binary( binaries )
{
  binary  = chomp( binary );
  teamViwVer = get_bin_version( full_prog_name:binary, sock:sock, version_argv:"--version", ver_pattern:"TeamViewer.*([0-9][0-9]+\.[0-9]+\.[0-9]+)");
  if(teamViwVer[1] )
  {
    set_kb_item( name:"TeamViewer/Linux/Ver", value:teamViwVer[1] );
    set_kb_item( name:"TeamViewer/Linux/detected", value:TRUE );

    cpe = build_cpe( value:teamViwVer[1], exp:"^([0-9.]+)", base:"cpe:/a:teamviewer:teamviewer:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:teamviewer:teamviewer";

    register_and_report_cpe(app:"TeamViewer",
                            ver:teamViwVer[1],
                            base:"cpe:/a:teamviewer:teamviewer:",
                            expr:"^([0-9.]+)",
                            insloc:binary,
                            concluded:teamViwVer[0]);
  exit(0);
  }
}
ssh_close_connection();
exit(0);
