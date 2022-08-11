###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnu_bash_detect_lin.nasl 12551 2018-11-27 14:35:38Z cfischer $
#
# GNU Bash Version Detection (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108258");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12551 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-27 15:35:38 +0100 (Tue, 27 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-20 12:31:0 +0200 (Fri, 20 Oct 2017)");
  script_name("GNU Bash Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of GNU bash.

  The script logs in via SSH, searches for the executable 'bash' and queries the
  found executables via the command line option '--version'");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

binaries = find_file( file_name:"bash", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock );

foreach binary( binaries ) {

  binary  = chomp( binary );
  version = get_bin_version( full_prog_name:binary, sock:sock, version_argv:"--version", ver_pattern:"GNU bash, version ([0-9.]+)" );

  if( version[1] ) {

    set_kb_item( name:"bash/linux/ver", value:version[1] );
    set_kb_item( name:"bash/linux/detected", value:TRUE );
    found = TRUE;

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:gnu:bash:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:gnu:bash";

    register_product( cpe:cpe, location:binary, port:0, service:"ssh-login" );

    log_message( data:build_detection_report( app:"GNU bash",
                                              version:version[1],
                                              install:binary,
                                              cpe:cpe,
                                              concluded:version[0] ) );
  }
}

# Fallback for the Shellshock NVTs as a last resort if the detection above doesn't work
# against some special devices / systems.
if( ! found ) {
  result = ssh_cmd( socket:sock, cmd:"bash --version", nosh:TRUE );
  if( "GNU bash" >< result ) {

    version = "unknown";
    install = "unknown";
    set_kb_item( name:"bash/linux/detected", value:TRUE );

    vers = eregmatch( pattern:"GNU bash, version ([0-9.]+)", string:result );
    if( vers[1] ) {
      version = vers[1];
      set_kb_item( name:"bash/linux/ver", value:version );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:gnu:bash:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:gnu:bash";

    register_product( cpe:cpe, location:install, port:0, service:"ssh-login" );

    log_message( data:build_detection_report( app:"GNU bash",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ) );

  }
}

ssh_close_connection();
exit( 0 );
