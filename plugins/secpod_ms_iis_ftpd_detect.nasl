##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_ftpd_detect.nasl 13501 2019-02-06 13:06:00Z cfischer $
#
# Microsoft IIS FTP Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900875");
  script_version("$Revision: 13501 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 14:06:00 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft IIS FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/microsoft/iis_ftp/detected");

  script_tag(name:"summary", value:"Detection of Microsoft IIS FTP Server.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");

port   = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# 220 $hostname Microsoft FTP Service (Version 5.0).
# 220 $hostname Microsoft FTP Service (Version 3.0).
if( banner && egrep( pattern:".*icrosoft FTP.*", string:banner ) ) {

  install = port + "/tcp";
  version = "unknown";

  set_kb_item( name:"MS/IIS-FTP/Installed", value:TRUE );

  ver = eregmatch( pattern:"Microsoft FTP Service \(Version ([0-9.]+)\)", string:banner, icase:TRUE );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    set_kb_item( name:"MS/IIS-FTP/Ver", value:version );
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:ftp_service:");
  if( isnull( cpe ) )
    cpe = "cpe:/a:microsoft:ftp_service";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"Microsoft IIS FTP Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );