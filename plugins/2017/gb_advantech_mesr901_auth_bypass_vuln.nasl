##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_mesr901_auth_bypass_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Advantech MESR901 Authentication Bypass Vulnerability
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

CPE = "cpe:/a:advantech:mesr901";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106843");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-02 11:02:25 +0700 (Fri, 02 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7909");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Advantech MESR901 Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_advantech_mesr901_detect.nasl");
  script_mandatory_keys("advantech_mesr901/detected");

  script_tag(name:"summary", value:"Advantech MESR901 is prone to an authentication bypass vulnerability.");

  script_tag(name:"insight", value:"The web interface uses JavaScript to check client authentication and
redirect unauthorized users. Attackers may intercept requests and bypass authentication to access restricted web
pages.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET Request and checks the response.");

  script_tag(name:"affected", value:"Advantech MESR901 firmware versions 1.5.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-122-03");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/network.html";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("I want DHCP to setup the network" >< res && "validateIPAddrAndGateway(this)" >< res) {
  report = "It was possible to access " + report_vuln_url(port: port, url: url, url_only: TRUE) +
           " without authentication.\n";

  gateway = eregmatch(pattern: 'default_gateway.* VALUE="([0-9.]+)" CLASS', string: res);
  if (!isnull(gateway[1]))
    report += "\nThis is the obtained default gateway of the MESR901:     " + gateway[1];

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
