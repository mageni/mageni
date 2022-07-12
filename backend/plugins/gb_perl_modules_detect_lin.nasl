###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_modules_detect_lin.nasl 12740 2018-12-10 11:49:57Z cfischer $
#
# Perl Modules Detection (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:perl:perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108504");
  script_version("$Revision: 12740 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 12:49:57 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-10 09:46:38 +0100 (Mon, 10 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Perl Modules Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_perl_detect_lin.nasl");
  script_mandatory_keys("perl/linux/detected");

  script_tag(name:"summary", value:"Detects the version of various installed Perl
  modules via SSH.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

if( isnull( port = get_app_port( cpe:CPE, service:"ssh-login" ) ) )
  exit( 0 );

if( ! bin = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

cmd = string( bin, " -MArchive::Tar -e 'print ", '"$Archive::Tar::VERSION"', "'" );
version = ssh_cmd( socket:sock, cmd:cmd, timeout:60, nosh:TRUE );
version = chomp( version );
if( version && "not found" >!< version && "@INC" >!< version && version =~ "^[0-9.]+$" ) {
  set_kb_item( name:"perl/linux/modules/detected", value:TRUE );
  set_kb_item( name:"perl/linux/modules/archive_tar/detected", value:TRUE );
  register_and_report_cpe( app:"Perl Module Archive::Tar", ver:version, base:"cpe:/a:perl:archive_tar:", expr:"([0-9.]+)", regPort:0, insloc:bin, concluded:version, regService:"ssh-login" );
}

cmd = string( bin, " -MCGI -e 'print ", '"$CGI::VERSION"', "'" );
version = ssh_cmd( socket:sock, cmd:cmd, timeout:60, nosh:TRUE );
version = chomp( version );
if( version && "not found" >!< version && "@INC" >!< version && version =~ "^[0-9.]+$" ) {
  set_kb_item( name:"perl/linux/modules/detected", value:TRUE );
  set_kb_item( name:"perl/linux/modules/cgi/detected", value:TRUE );
  register_and_report_cpe( app:"Perl Module CGI", ver:version, base:"cpe:/a:andy_armstrong:cgi.pm:", expr:"([0-9.]+)", regPort:0, insloc:bin, concluded:version, regService:"ssh-login" );
}

cmd = string( bin, " -MIO::Socket::SSL -e 'print ", '"$IO::Socket::SSL::VERSION"', "'" );
version = ssh_cmd( socket:sock, cmd:cmd, timeout:60, nosh:TRUE );
version = chomp( version );
if( version && "not found" >!< version && "@INC" >!< version && version =~ "^[0-9.]+$" ) {
  set_kb_item( name:"perl/linux/modules/detected", value:TRUE );
  set_kb_item( name:"perl/linux/modules/io_socket_ssl/detected", value:TRUE );
  register_and_report_cpe( app:"Perl Module IO::Socket::SSL", ver:version, base:"cpe:/a:io-socket-ssl:io-socket-ssl:", expr:"([0-9.]+)", regPort:0, insloc:bin, concluded:version, regService:"ssh-login" );
}

cmd = string( bin, " -MSafe -e 'print ", '"$Safe::VERSION"', "'" );
version = ssh_cmd( socket:sock, cmd:cmd, timeout:60, nosh:TRUE );
version = chomp( version );
if( version && "not found" >!< version && "@INC" >!< version && version =~ "^[0-9.]+$" ) {
  set_kb_item( name:"perl/linux/modules/detected", value:TRUE );
  set_kb_item( name:"perl/linux/modules/safe/detected", value:TRUE );
  register_and_report_cpe( app:"Perl Module Safe", ver:version, base:"cpe:/a:rafael_garcia-suarez:safe:", expr:"([0-9.]+)", regPort:0, insloc:bin, concluded:version, regService:"ssh-login" );
}

ssh_close_connection();
exit( 0 );