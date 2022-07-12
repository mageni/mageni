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
  script_oid("1.3.6.1.4.1.25623.1.0.117584");
  script_version("2021-07-30T07:03:45+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-5139", "CVE-2014-3511", "CVE-2014-3512");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20140806 - 2) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-5139: A crash was found affecting SRP ciphersuites used in a Server Hello message. The
  issue affects OpenSSL clients and allows a malicious server to crash the client with a null
  pointer dereference (read) by specifying an SRP ciphersuite even though it was not properly
  negotiated with the client. This could lead to a Denial of Service.

  - CVE-2014-3511: A flaw in the OpenSSL SSL/TLS server code causes the server to negotiate TLS 1.0
  instead of higher protocol versions when the ClientHello message is badly fragmented. This allows
  a man-in-the-middle attacker to force a downgrade to TLS 1.0 even if both the server and the
  client support a higher protocol version, by modifying the client's TLS records.

  - CVE-2014-3512: A SRP buffer overrun was found. A malicious client or server can send invalid SRP
  parameters and overrun an internal buffer. Only applications which are explicitly set up for SRP
  use are affected.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.1 through 1.0.1h.");

  script_tag(name:"solution", value:"Update to version 1.0.1i or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20140806.txt");

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

if (version_in_range(version: version, test_version: "1.0.1", test_version2: "1.0.1h")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.1i", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);