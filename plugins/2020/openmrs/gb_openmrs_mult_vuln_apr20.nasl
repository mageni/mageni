# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:openmrs:openmrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143678");
  script_version("2020-04-07T05:44:07+0000");
  script_tag(name:"last_modification", value:"2020-04-07 10:46:07 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-07 04:42:06 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-5728", "CVE-2020-5729", "CVE-2020-5730", "CVE-2020-5731", "CVE-2020-5732",
                "CVE-2020-5733");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenMRS <= 2.9.0 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openmrs_detect.nasl");
  script_mandatory_keys("openmrs/detected");

  script_tag(name:"summary", value:"OpenMRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"OpenMRS is prone to multiple vulnerabilities:

  - XSS in UIFramework Error Page

  - XSS via Referrer Headers and Arbitrary Parameters

  - XSS in Login Page's sessionLocation parameter

  - XSS in ActiveVisit page's app parameter

  - Authentication Bypass for Data Import

  - Authentication Bypass for Data Export");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-18");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/module/dataexchange/export.form";
headers = make_array("Content-Type", "application/x-www-form-urlencoded");
data = "conceptIds=1";

req = http_post_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 201" && "concept_datatype_id" >< res) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
