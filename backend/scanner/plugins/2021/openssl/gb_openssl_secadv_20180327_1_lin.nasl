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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150704");
  script_version("2021-07-30T07:03:45+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-0739");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20180327) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Constructed ASN.1 types with a recursive definition (such as can
  be found in PKCS7) could eventually exceed the stack given malicious input with excessive
  recursion. This could result in a Denial Of Service attack. There are no such structures used
  within SSL/TLS that come from untrusted sources so this is considered safe. Reported by
  OSS-fuzz.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2b through 1.0.2n and 1.1.0 through 1.1.0g.");

  script_tag(name:"solution", value:"Update to version 1.0.2o, 1.1.0h or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180327.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.0g")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.0h", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2n")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2o", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);