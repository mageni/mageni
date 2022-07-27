###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dns_info_discl_vuln.nasl 12270 2018-11-09 07:08:54Z cfischer $
#
# D-Link DNS Devices Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:d-link";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106016");
  script_version("$Revision: 12270 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-09 08:08:54 +0100 (Fri, 09 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("D-Link DNS Devices Multiple Information Disclosure Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dns_device");

  script_xref(name:"URL", value:"http://www.search-lab.hu/media/D-Link_Security_advisory_3_0_public.pdf");

  script_tag(name:"summary", value:"Multiple information disclosure vulnerabilities in D-Link DNS
  series devices.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"D-Link DNS series devices allow unauthenticated attackers to gain
  system information. The CGI scripts info.cgi, discovery.cgi, status_mgr.cgi, widget_api.cgi, wizard_mgr.cgi
  and app_mgr.cgi give detailed information about the settings and versions of the system back.");

  script_tag(name:"impact", value:"An unauthenticated attacker can gain information about the system and
  its configuration which will help to customize further attacks.");

  script_tag(name:"affected", value:"DNS-320, DNS-320L, DNS-325, DNS-327L. Other devices, models or versions
  might be also affected.");

  script_tag(name:"solution", value:"Update the Firmware to the latest available version.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit( 0 );

if (dir == "/")
  dir = "";

url = dir + "/cgi-bin/info.cgi";
if (http_vuln_check(port: port, url: url, pattern: "Product=",
                    extra_check: "Model=", check_header: TRUE)) {
  report = report_vuln_url( port:port, url:url );
  security_message(port: port, data:report);
  exit(0);
}

url = dir + "/cgi-bin/discovery.cgi";
if (http_vuln_check(port: port, url: url, pattern: "<entry>",
                    extra_check: "<ConnectType>", check_header: TRUE)) {
  report = report_vuln_url( port:port, url:url );
  security_message(port: port, data:report);
  exit(0);
}

url = dir + "/cgi-bin/status_mgr.cgi?cmd=cgi_get_status";
if (http_vuln_check(port: port, url: url, pattern: "<status>",
                    extra_check: "<uptime>", check_header: TRUE)) {
  report = report_vuln_url( port:port, url:url );
  security_message(port: port, data:report);
  exit(0);
}

exit(99);