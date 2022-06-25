# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.806729");
  script_version("2021-07-29T12:32:36+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-29 12:32:36 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2015-11-24 18:49:30 +0530 (Tue, 24 Nov 2015)");

  script_cve_id("CVE-2015-1787", "CVE-2015-0290", "CVE-2015-0291", "CVE-2015-0285", "CVE-2015-0208",
                "CVE-2015-0207");

  script_bugtraq_id(73238, 73226, 73235, 73234, 73229);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20150319 - 2) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-1787: Empty CKE with client auth and DHE. If client auth is used then a server can seg
  fault in the event of a DHE ciphersuite being selected and a zero length ClientKeyExchange message
  being sent by the client. This could be exploited in a DoS attack.

  - CVE-2015-0290: Multiblock corrupted pointer. OpenSSL 1.0.2 introduced the 'multiblock'
  performance improvement. This feature only applies on 64 bit x86 architecture platforms that
  support AES NI instructions. A defect in the implementation of 'multiblock' can cause OpenSSL's
  internal write buffer to become incorrectly set to NULL when using non-blocking IO. Typically,
  when the user application is using a socket BIO for writing, this will only result in a failed
  connection. However if some other BIO is used then it is likely that a segmentation fault will be
  triggered, thus enabling a potential DoS attack.

  - CVE-2015-0291: ClientHello sigalgs DoS. If a client connects to an OpenSSL 1.0.2 server and
  renegotiates with an invalid signature algorithms extension a NULL pointer dereference will occur.
  This can be exploited in a DoS attack against the server.

  - CVE-2015-0285: Under certain conditions an OpenSSL 1.0.2 client can complete a handshake with an
  unseeded PRNG. If the handshake succeeds then the client random that has been used will have been
  generated from a PRNG with insufficient entropy and therefore the output may be predictable.

  - CVE-2015-0208: Segmentation fault for invalid PSS parameters. The signature verification
  routines will crash with a NULL pointer dereference if presented with an ASN.1 signature using the
  RSA PSS algorithm and invalid parameters. Since these routines are used to verify certificate
  signature algorithms this can be used to crash any certificate verification operation and
  exploited in a DoS attack. Any application which performs certificate verification is vulnerable
  including OpenSSL clients and servers which enable client authentication.

  - CVE-2015-0207: Segmentation fault in DTLSv1_listen. A defect in the implementation of
  DTLSv1_listen means that state is preserved in the SSL object from one invocation to the next that
  can lead to a segmentation fault. Errors processing the initial ClientHello can trigger this
  scenario. An example of such an error could be that a DTLS1.0 only client is attempting to connect
  to a DTLS1.2 only server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct brute-force attack, to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2.");

  script_tag(name:"solution", value:"Update to version 1.0.2a or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031929");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"1.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2a", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);