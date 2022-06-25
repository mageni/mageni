###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mult_ip_cameras_mult_vuln.nasl 14045 2019-03-08 07:18:46Z cfischer $
#
# Multiple IP-Cameras (P2P) WIFICAM Cameras Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.106636");
  script_version("$Revision: 14045 $");
  script_cve_id("CVE-2017-8224", "CVE-2017-8222", "CVE-2017-8225", "CVE-2017-8223", "CVE-2017-8221");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 08:18:46 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-08 12:16:59 +0700 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple IP-Cameras (P2P) WIFICAM Cameras Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_tag(name:"summary", value:"The IP-Camera is prone to multiple vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request to read the system configuration and checks
  the response.");

  script_tag(name:"insight", value:"Multiple IP-Cameras are prone to multiple vulnerabilities:

  - Backdoor account

  - RSA key and certificates

  - Pre-Auth Info Leak (credentials) within the GoAhead http server

  - Authenticated RCE as root

  - Pre-Auth RCE as root

  - Streaming without authentication

  - Unsecure Cloud functionality");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code and read arbitrary
  files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3043");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  exit(0);
}

include("dump.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 81);

url = "/system.ini?loginuse&loginpas";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

tmp = bin2string(ddata: res, noprint_replacement: " ");
if (strlen(res) > 4000 && (egrep(pattern: "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", string: tmp) ||
    "IPCAM" >< res || "admin" >< res)) {
  if (http_vuln_check(port: port, url: "login.cgi", pattern: 'var loginpass=".*";', check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);