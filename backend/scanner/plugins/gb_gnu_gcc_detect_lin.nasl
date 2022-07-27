###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnu_gcc_detect_lin.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# GCC Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806083");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 11:46:09 +0530 (Tue, 13 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("GCC Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of GCC.

  The script logs in via ssh, searches for executable 'gcc' and queries the
  found executables via command line option '-v'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

gcc_sock = ssh_login_or_reuse_connection();
if( ! gcc_sock ) exit( 0 );

gccName = find_file( file_name:"gcc", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:gcc_sock );

foreach binary_gccName( gccName ) {

  binary_name = chomp( binary_gccName );
  gccVer = get_bin_version( full_prog_name:binary_name, sock:gcc_sock,
                            version_argv:"-v", ver_pattern:"gcc-" +
                            "([0-9.]+)" );

  if( gccVer[1] ) {

    ##If version ends with '.' remove that, example 1.2.3.
    gccVersion = ereg_replace( string:gccVer[1], pattern:"\.$", replace:"" );

    set_kb_item( name:"gcc/Linux/Ver", value:gccVersion );

    cpe = build_cpe( value:gccVersion, exp:"^([0-9.]+)", base:"cpe:/a:gnu:gcc:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:gnu:gcc";

    register_product( cpe:cpe, location:binary_name );

    log_message( data:build_detection_report( app:"GNU GCC",
                                              version:gccVersion,
                                              install:binary_name,
                                              cpe:cpe,
                                              concluded:gccVer[0] ) );
  }
}

ssh_close_connection();
exit( 0 );