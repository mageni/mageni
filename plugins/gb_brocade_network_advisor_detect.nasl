###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_network_advisor_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Brocade Network Advisor Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106515");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-01-16 10:12:31 +0700 (Mon, 16 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brocade Network Advisor Detection");

  script_tag(name:"summary", value:"Detection of Brocade Network Advisor

  The script sends a HTTP connection request to the server and attempts to detect the presence of Brocade Network
  Advisor and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.brocade.com/de/products-services/network-management/brocade-network-advisor.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/login.xhtml");

if ("<title>Network Advisor Login</title>" >< res && 'ui-menuitem-text">About Network Advisor' >< res) {
  version = "unknown";

  cookie = eregmatch(pattern: "Set-Cookie: (JSESSIONID=[^;]+)", string: res);
  if (!isnull(cookie[1]))
    cookie = cookie[1];


  viewstate = eregmatch(pattern: 'javax.faces.ViewState(..)?" value="([^"]+)', string: res);
  if (!isnull(viewstate[2]))
    viewstate = urlencode(str: viewstate[2]);

  data = "javax.faces.partial.ajax=true&javax.faces.source=aboutDialog&javax.faces.partial.execute=aboutDialog&javax.faces.partial.render=aboutDialog&aboutDialog=aboutDialog&aboutDialog_contentLoad=true&loginForm=loginForm&loginForm%3Akey=&loginForm%3Avalue=&javax.faces.ViewState=" + viewstate;

  req = http_post_req(port: port, url: "/login.xhtml", data: data, add_headers: make_array("Content-Type",
                      "application/x-www-form-urlencoded; charset=UTF-8", "Cookie", cookie));
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: "Network Advisor ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "brocade_network_advisor/version", value: version);
  }

  set_kb_item(name: "brocade_network_advisor/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:brocade:network_advisor:");
  if (!cpe)
    cpe = 'cpe:/a:brocade:network_advisor';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Brocade Network Advisor", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
