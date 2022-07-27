##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_ip_office_detect.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Avaya IP Office Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106322");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Avaya IP Office Detection");

  script_tag(name:"summary", value:"Detection of Avaya IP Office.

  The script sends a connection request to the server and attempts to detect the presence of Avaya IP Office and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://support.avaya.com/products/P0160/ip-office-platform");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'GET /index.html HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Connection: close\r\n\r\n';
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>About IP Office" >< res && "<o:Company>Avaya</o:Company>" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "Version: ([0-9.]+) \(([0-9]+)\)", string: res);
  if(!isnull(vers[1]) && !isnull(vers[2])) {
    version = vers[1] + '.' + vers[2];
    set_kb_item(name: "avaya_ip_office/version", value: version);
  }

  set_kb_item(name: "avaya_ip_office/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:ip_office:");
  if (!cpe)
    cpe = 'cpe:/a:avaya:ip_office';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Avaya IP Office", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
