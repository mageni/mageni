###############################################################################
# OpenVAS Vulnerability Test
#
# HHVM Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105140");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2019-05-17T09:31:40+0000");
  script_tag(name:"last_modification", value:"2019-05-17 09:31:40 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-09 14:29:24 +0100 (Tue, 09 Dec 2014)");
  script_name("HHVM Detection");

  script_xref(name:"URL", value:"http://hhvm.com/");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HHVM/banner");

  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner || "X-Powered-By: HHVM/" >!< banner ) exit( 0 );

vers = 'unknown';
version = eregmatch( pattern:'X-Powered-By: HHVM/([^ \r\n]+)', string:banner );
if( ! isnull( version[1] ) ) vers = version[1];

set_kb_item(name:"HHVM/detected",value:TRUE);

cpe = build_cpe( value:vers, exp:"^([0-9.]+.*)$", base:"cpe:/a:facebook:hhvm:" );
if( ! cpe )
  cpe = "cpe:/a:facebook:hhvm";

register_product( cpe:cpe, location:port + '/', port:port, service:"www" );

log_message( data: build_detection_report( app:"HHVM",
                                           version:vers,
                                           install:'/',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );

exit(0);
