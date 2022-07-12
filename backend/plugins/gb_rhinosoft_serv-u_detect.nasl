###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rhinosoft_serv-u_detect.nasl 13615 2019-02-12 17:41:28Z cfischer $
#
# Rhino Software Serv-U SSH and FTP Server Version Detection (Remote)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801117");
  script_version("$Revision: 13615 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 18:41:28 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  # Now known as Solarwinds Serv-U FTP Server
  # http://clearygull.com/project/rhino-software-inc-sold-to-solarwinds/
  # https://www.solarwinds.com/de/serv-u-managed-file-transfer-server
  script_name("Rhino Software Serv-U SSH and FTP Server Version Detection (Remote)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ftp", 21, 990, "Services/ssh", 22);
  script_mandatory_keys("ssh_or_ftp/serv-u/detected");

  script_tag(name:"summary", value:"This script detects the installed version of Rhino Software
  Serv-U and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

ftpPorts = ftp_get_ports();
foreach port( ftpPorts ) {

  banner = get_ftp_banner( port:port );
  if( ! banner || "Serv-U" >!< banner )
    continue;

  set_kb_item( name:"Serv-U/FTP/installed", value:TRUE );
  set_kb_item( name:"Serv-U/detected", value:TRUE );
  vers = "unknown";
  install = port + '/tcp';

  version = eregmatch( pattern:"Serv-U FTP Server v([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    set_kb_item( name:"Serv-U/FTP/Ver", value:vers );
    set_kb_item( name:"ftp/" + port + "/Serv-U", value:vers );
  } else {
    # Response to CSID command (See get_ftp_banner() in ftp_func.inc)
    version = eregmatch( string:banner, pattern:"Name=Serv-U; Version=([^;]+);" );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
      set_kb_item( name:"Serv-U/FTP/Ver", value:vers );
      set_kb_item( name:"ftp/" + port + "/Serv-U", value:vers );
    }
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:rhinosoft:serv-u:" );
  if( ! cpe )
    cpe = "cpe:/a:rhinosoft:serv-u";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"Rhino Software Serv-U FTP Server",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:banner ),
                                            port:port );
}

sshPort = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:sshPort );

# SSH-2.0-Serv-U_10.3.0.1
if( banner && "serv-u" >< tolower( banner ) ) {

  vers = "unknown";
  set_kb_item( name:"Serv-U/SSH/detected", value:TRUE );
  set_kb_item( name:"Serv-U/detected", value:TRUE );
  install = sshPort + '/tcp';

  version = eregmatch( pattern:"Serv-U_([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    set_kb_item( name:"Serv-U/SSH/Ver", value:vers );
    set_kb_item( name:"ssh/" + sshPort + "/Serv-U", value:vers );
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:rhinosoft:serv-u:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:rhinosoft:serv-u';

  register_product( cpe:cpe, location:install, port:sshPort, service:"ssh" );

  log_message( data:build_detection_report( app:"Rhino Software Serv-U SSH Server",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:banner ),
                                            port:sshPort );
}

exit( 0 );