###################################################################
# OpenVAS Vulnerability Test
#
# Cisco IDS Manager Detection
#
# LSS-NVT-2009-006
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102006");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CISCO IDS Manager Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects if CISCO IDS Manager is running on a given host and port.

  The IDS Device Manager is a web-based Java application that resides
  on the sensor and is accessed via a secure, encrypted TLS link using
  standard Netscape and Internet Explorer web browsers to perform
  various management and monitoring tasks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:443);
body = http_get_cache(item:"/", port:port);

if("<title>Cisco Systems IDS Device Manager</title>" >< body){

  set_kb_item(name:"Services/www/cisco_ids_manager", value:TRUE);
  http_set_is_marked_embedded(port:port);

  ## CPE is currently not registered
  cpe = 'cpe:/a:cisco:ids_device_manager';

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data: build_detection_report( app:"Cisco IDS Device Manager",
                                             install:port + '/tcp',
                                             cpe:cpe),
                                             port:port);
}

exit(0);