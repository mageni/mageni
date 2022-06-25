###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mango_automation_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Mango Automation Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806064");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-01 12:11:26 +0530 (Thu, 01 Oct 2015)");
  script_name("Mango Automation Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Mango Automation.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

rcvRes = http_get_cache( item: "/login.htm", port:port );

if( 'content="Mango Automation' >< rcvRes && 'Login' >< rcvRes && 'Infinite Automation Systems' >< rcvRes ) {

  install = "/";
  version = "unknown";

  set_kb_item( name:"www/" + port + "/Mango Automation", value:version );
  set_kb_item( name:"Mango Automation/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:infinite_automation_systems:mango_automation:" );
  if( ! cpe )
    cpe = "cpe:/a:infinite_automation_systems:mango_automation";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Mango Automation",
                                            version:version,
                                            install:install,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );