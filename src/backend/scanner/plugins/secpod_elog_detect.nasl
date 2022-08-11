###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elog_detect.nasl 9889 2018-05-17 14:03:49Z cfischer $
#
# ELOG Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901008");
  script_version("$Revision: 9889 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-17 16:03:49 +0200 (Thu, 17 May 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ELOG Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ELOG_HTTP/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"This script finds the running ELOG Version and saves the
  result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( "erver: ELOG" >!< banner ) exit( 0 );

install = port + "/tcp";
version = "unknown";

vers = eregmatch( pattern:"Server: ELOG HTTP (([0-9.]+)-?([0-9]+)?)", string:banner, icase:TRUE );
if( ! isnull( vers[1] ) ) version = ereg_replace( pattern:"-", string:vers[1], replace:"." );

set_kb_item( name:"www/" + port + "/ELOG", value:version );
set_kb_item( name:"ELOG/detected", value:TRUE );
register_and_report_cpe( app:"ELOG", ver:version, concluded:vers[0], base:"cpe:/a:stefan_ritt:elog_web_logbook:", expr:"^([0-9]+\.[0-9]+\.[0-9]+)", insloc:install, regPort:port );

exit( 0 );
