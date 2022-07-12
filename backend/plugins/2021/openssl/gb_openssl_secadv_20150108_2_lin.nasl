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
  script_oid("1.3.6.1.4.1.25623.1.0.117580");
  script_version("2021-07-30T07:03:45+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-0205", "CVE-2015-0206");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20150108 - 2) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-0206: A memory leak can occur in the dtls1_buffer_record function under certain
  conditions. In particular this could occur if an attacker sent repeated DTLS records with the same
  sequence number but for the next epoch. The memory leak could be exploited by an attacker in a
  Denial of Service attack through memory exhaustion.

  - CVE-2015-0205: An OpenSSL server will accept a DH certificate for client authentication without
  the certificate verify message. This effectively allows a client to authenticate without the use
  of a private key. This only affects servers which trust a client certificate authority which
  issues certificates containing DH keys: these are extremely rare and hardly ever encountered.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.0 through 1.0.0o and 1.0.1 through 1.0.1j.");

  script_tag(name:"solution", value:"Update to version 1.0.0p, 1.0.1k or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150108.txt");

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

if (version_in_range(version: version, test_version: "1.0.0", test_version2: "1.0.0o")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.0p", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.1", test_version2: "1.0.1j")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.1k", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);