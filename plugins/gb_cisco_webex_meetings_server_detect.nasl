###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_webex_meetings_server_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco WebEx Meetings Server Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106191");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-19 11:08:48 +0700 (Fri, 19 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco WebEx Meetings Server Detection");

  script_tag(name:"summary", value:"Detection of Cisco WebEx Meetings Server

The script sends a connection request to the server and attempts to detect the presence of Cisco WebEx Meetings
Server and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/conferencing/webex-meetings-server/index.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = "/orion/login";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (("Cisco WebEx</title>" >< res || ">Cisco WebEx Meetings Server</title>" >< res) &&
     'title="Cisco WebEx Meetings Server"' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "CWMS\/([0-9_]+)\/FAQs.html", string: res);
  if(!vers){
    vers = eregmatch(pattern: "CWMS\/([0-9_]+)\/Localizations/FAQs", string: res);
  }
  if (!isnull(vers[1]))
    version = str_replace(string: vers[1], find: "_", replace: ".");

  set_kb_item(name: "cisco/webex/detected", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "cisco/webex/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:webex_meetings_server:");
  if (!cpe)
    cpe = 'cpe:/a:cisco:webex_meetings_server';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Cisco WebEx Meetings Server", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
