###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alcatel_luc_omnvista_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Alcatel-Lucent Omnivista Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107113");
  script_version("$Revision: 10888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-22 06:40:16 +0200 (Thu, 22 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Alcatel-Lucent Omnivista Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Alcatel-Lucent Omnivista.

  The script detects the version of Alcatel Lucent Omnivista on remote host and sets the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port( default:80 );

url = '/';

rcvRes = http_get_cache( port:appPort, item:"/" );

if ( rcvRes =~ "^HTTP/1\.[01] 200" && "<title>Alcatel-Lucent OmniVista" >< rcvRes ) {

  alclucomnivistaVer = "unknown";

  tmpVer = eregmatch( string:rcvRes, pattern:"Alcatel-Lucent OmniVista ([0-9]+)", icase:TRUE );
  if( tmpVer[1] ) {
    alclucomnvistaVer = tmpVer[1];
    set_kb_item( name:"www/" + appPort + "/alc", value:alclucomnvistaVer );
  }

  set_kb_item( name:"alc-luc-omnvista/installed", value:TRUE );

  cpe = build_cpe( value:alclucomnvistaVer, exp:"^([0-9.]+)", base:"cpe:/a:alcatel-lucent:omnivista:" );
  if( ! cpe )
    cpe = 'cpe:/a:alcatel-lucent:omnivista';

  register_product( cpe:cpe, location:appPort + '/tcp', port:appPort );
  log_message( data:build_detection_report( app:"Alcatel-Lucent Omnivista",
                                            version:alclucomnvistaVer,
                                            install:appPort + '/tcp',
                                            cpe:cpe,
                                            concluded:tmpVer[0] ),
                                            port:appPort );
}

exit( 0 );
