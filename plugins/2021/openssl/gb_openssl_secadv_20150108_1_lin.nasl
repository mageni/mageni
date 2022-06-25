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
  script_oid("1.3.6.1.4.1.25623.1.0.150705");
  script_version("2021-07-30T07:03:45+0000");
  script_tag(name:"last_modification", value:"2021-07-30 07:03:45 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2014-3571", "CVE-2014-3569", "CVE-2014-3572", "CVE-2015-0204", "CVE-2014-8275",
                "CVE-2014-3570");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20150108 - 1) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-3571: A carefully crafted DTLS message can cause a segmentation fault in OpenSSL due to
  a NULL pointer dereference. This could lead to a Denial Of Service attack.

  - CVE-2014-3569: When openssl is built with the no-ssl3 option and a SSL v3 ClientHello is
  received the ssl method would be set to NULL which could later result in a NULL pointer
  dereference.

  - CVE-2014-3572: An OpenSSL client will accept a handshake using an ephemeral ECDH ciphersuite
  using an ECDSA certificate if the server key exchange message is omitted. This effectively
  removes forward secrecy from the ciphersuite.

  - CVE-2015-0204: An OpenSSL client will accept the use of an RSA temporary key in a non-export RSA
  key exchange ciphersuite. A server could present a weak temporary key and downgrade the security
  of the session.

  - CVE-2014-8275: OpenSSL accepts several non-DER-variations of certificate signature algorithm and
  signature encodings. OpenSSL also does not enforce a match between the signature algorithm between
  the signed and unsigned portions of the certificate. By modifying the contents of the signature
  algorithm or the encoding of the signature, it is possible to change the certificate's fingerprint.

  - CVE-2014-3570: Bignum squaring (BN_sqr) may produce incorrect results on some platforms,
  including x86_64. This bug occurs at random with a very low probability, and is not known to be
  exploitable in any way, though its exact impact is difficult to determine.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8zc, 1.0.0 through 1.0.0o and
  1.0.1 through 1.0.1j.");

  script_tag(name:"solution", value:"Update to version 0.9.8zd, 1.0.0p, 1.0.1k or later.");

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

if (version_in_range(version: version, test_version: "0.9.8", test_version2: "0.9.8zc")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8zd", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

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