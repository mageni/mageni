##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_loxone_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Loxone Miniserver Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107044");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-07 13:18:59 +0200 (Wed, 07 Sep 2016)");
  script_name("Loxone Miniserver Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Loxone Miniserver");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Loxone/banner");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");

http_port = get_http_port(default:80);
Banner = get_http_banner(port: http_port);

if( Banner && "Server: Loxone" >< Banner ) {

  set_kb_item( name:"loxone/web/detected", value:TRUE );

  vers = 'unknown';
  version = eregmatch( pattern:'Server: Loxone ([0-9.]+)', string:Banner );

  cpe = 'cpe:/a:loxone:loxone';
  if( !isnull (version[1] ) )  vers = version[1];

  if( vers != 'unknown')   cpe += ':' + vers;

  register_product( cpe:cpe, location: '/', port:http_port, service:'www' );

  report = build_detection_report( app:'Loxone Miniserver',
                                   version:vers,
                                   install:'/',
                                   cpe:cpe,
                                   concluded:version[0]);

  log_message( port:http_port, data:report );
}

exit( 0 );





