###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_pure-ftpd_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Pure-FTPd FTP Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111110");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-07-12 17:00:00 +0200 (Tue, 12 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Pure-FTPd FTP Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pure_ftpd/detected");

  script_tag(name:"summary", value:"The script is grabbing the banner of a FTP server
  and sends a 'HELP' command to identify a Pure-FTPd FTP Server from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("cpe.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
command = get_ftp_cmd_banner( port:port, cmd:"HELP" );

if( "Welcome to Pure-FTPd" >< banner || "Welcome to PureFTPd" >< banner ) {
  installed = TRUE;
  concluded = banner;
} else if( "Pure-FTPd - http://pureftpd.org" >< command ) {
  installed = TRUE;
  concluded = command;
}

if( installed ) {

  install = port + '/tcp';
  version = "unknown";

  ver = eregmatch( pattern:"Welcome to PureFTPd ([0-9.]+)", string:banner );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    concluded = ver[0];
  }

  set_kb_item( name:"ftp/" + port + "/pure-ftpd", value:version );
  set_kb_item( name:"pure-ftpd/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:pureftpd:pure-ftpd:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:pureftpd:pure-ftpd';

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"Pure-FTPd",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );