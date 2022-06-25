###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_harmonic_nsg_9000_devices_detect.nasl 10864 2018-08-09 15:04:27Z cfischer $
#
# Harmonic NSG 9000 Devices Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813746");
  script_version("$Revision: 10864 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 17:04:27 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 11:14:48 +0530 (Tue, 07 Aug 2018)");
  script_name("Harmonic NSG 9000 Devices Remote Detection");

  script_tag(name:"summary", value:"Detection of presence of Harmonic NSG 9000
  Device.

  The script sends a HTTP GET connection request to the server and attempts
  to determine if the remote host runs Harmonic NSG 9000 Device from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.harmonicinc.com/products/product-detail/nsg-9000-40g");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

nsgPort = get_http_port( default:80 );

banner = get_http_banner( port:nsgPort );
if(!banner){
  exit(0);
}

if(banner =~ "^HTTP/1\.[01] 401" && 'WWW-Authenticate: Basic realm="NSG9000"' >< banner )
{
  version = "unknown";
  install = nsgPort + "/tcp";
  set_kb_item( name:"nsg9000/detected", value:TRUE);
  set_kb_item( name:"nsgPort/http/port", value:nsgPort);

  # CPE not registered yet
  cpe = "cpe:/h:harmonic:nsg_9000";

  register_product(cpe:cpe, location:install, port:nsgPort, service:"www");

  log_message(data:build_detection_report(app:"Harmonic NSG 9000 Device",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version),
                                          port:nsgPort);
}

exit(0);
