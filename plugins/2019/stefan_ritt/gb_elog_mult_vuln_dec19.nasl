# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143249");
  script_version("2019-12-13T08:00:42+0000");
  script_tag(name:"last_modification", value:"2019-12-13 08:00:42 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-13 07:21:09 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-3992", "CVE-2019-3993", "CVE-2019-3994", "CVE-2019-3995", "CVE-2019-3996");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ELOG < 3.1.4-283534d Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");
  script_require_ports("Services/www", 8080, 443);

  script_tag(name:"summary", value:"ELOG is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"ELOG is prone to multiple vulnerabilities:

  - Configuration File Disclosure (CVE-2019-3992)

  - Password Hash Disclosure (CVE-2019-3993)

  - Use After Free (CVE-2019-3994)

  - NULL Pointer Dereference (CVE-2019-3995)

  - Unintended Proxy (CVE-2019-3996)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"ELOG versions prior to 3.1.4-283534d.");

  script_tag(name:"solution", value:"Update to version 3.1.4-283534d or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2019-53");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/?cmd=GetConfig";

if (http_vuln_check(port: port, url: url, pattern: 'filename="export.txt"', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
