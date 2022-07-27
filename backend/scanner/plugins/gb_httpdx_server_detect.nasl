###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_server_detect.nasl 13630 2019-02-13 11:03:59Z cfischer $
#
# httpdx Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800960");
  script_version("$Revision: 13630 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 12:03:59 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("httpdx Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/ftp", 21, 990);
  script_mandatory_keys("www_or_ftp/httpdx/detected");

  script_tag(name:"summary", value:"Detection of httpdx Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("http_func.inc");
include("host_details.inc");

ftpPorts = ftp_get_ports();
foreach port( ftpPorts ) {

  banner = get_ftp_banner( port:port );
  if( ! banner || "httpdx" >!< banner )
    continue;

  set_kb_item( name:"httpdx/installed", value:TRUE );
  vers = "unknown";
  install = port + "/tcp";

  httpdxVer = eregmatch( pattern:"httpdx.([0-9.]+[a-z]?)", string:banner );
  if( ! isnull( httpdxVer[1] ) ) {
    set_kb_item( name:"httpdx/" + port + "/Ver", value:httpdxVer[1] );
    vers = httpdxVer[1];
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+([a-z]+)?)", base:"cpe:/a:jasper:httpdx:" );
  if( ! cpe )
    cpe = "cpe:/a:jasper:httpdx";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"httpdx",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:httpdxVer[0] ),
                                            port:port );
}

if( http_is_cgi_scan_disabled() )
  exit( 0 );

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( banner && "httpdx/" >< banner ) {

  vers = "unknown";
  install = "/";
  httpdxVer = eregmatch( pattern:"httpdx.([0-9.]+[a-z]?)", string:banner );
  if( ! isnull( httpdxVer[1] ) ) {
    set_kb_item( name:"httpdx/" + port + "/Ver", value:httpdxVer[1] );
    vers = httpdxVer[1];
  }

  set_kb_item( name:"httpdx/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+([a-z]+)?)", base:"cpe:/a:jasper:httpdx:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:jasper:httpdx';

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"httpdx",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:httpdxVer[0] ),
                                            port:port );
}

exit( 0 );