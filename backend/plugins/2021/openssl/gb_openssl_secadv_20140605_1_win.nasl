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
  script_oid("1.3.6.1.4.1.25623.1.0.117598");
  script_version("2021-07-30T07:09:13+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:09:13 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-30 06:28:42 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-0160", "CVE-2014-0221", "CVE-2014-0195", "CVE-2014-3470");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20140605 - 1) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-0224: An attacker can force the use of weak keying material in OpenSSL SSL/TLS clients
  and servers. This can be exploited by a Man-in-the-middle (MITM) attack where the attacker can
  decrypt and modify traffic from the attacked client and server.

  - CVE-2014-0221: By sending an invalid DTLS handshake to an OpenSSL DTLS client the code can be
  made to recurse eventually crashing in a DoS attack. Only applications using OpenSSL as a DTLS
  client are affected.

  - CVE-2014-0195: A buffer overrun attack can be triggered by sending invalid DTLS fragments to an
  OpenSSL DTLS client or server. This is potentially exploitable to run arbitrary code on a
  vulnerable client or server. Only applications using OpenSSL as a DTLS client or server affected.

  - CVE-2014-3470: OpenSSL TLS clients enabling anonymous ECDH ciphersuites are subject to a denial
  of service attack.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8y, 1.0.0 through 1.0.0l and
  1.0.1 through 1.0.1g.");

  script_tag(name:"solution", value:"Update to version 0.9.8za, 1.0.0m, 1.0.1h or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20140605.txt");

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

if (version_in_range(version: version, test_version: "0.9.8", test_version2: "0.9.8y")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8za", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.0", test_version2: "1.0.0l")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.0m", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.1", test_version2: "1.0.1g")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.1h", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);