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
  script_oid("1.3.6.1.4.1.25623.1.0.147342");
  script_version("2021-12-16T06:20:27+0000");
  script_tag(name:"last_modification", value:"2021-12-16 11:53:28 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-16 06:11:37 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-4044");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Invalid handling of X509_verify_cert() internal errors (20211214) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to an invalid handling of X509_verify_cert()
  internal errors vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Internally libssl in OpenSSL calls X509_verify_cert() on the
  client side to verify a certificate supplied by a server. That function may return a negative
  return value to indicate an internal error (for example out of memory). Such a negative return
  value is mishandled by OpenSSL and will cause an IO function (such as SSL_connect() or
  SSL_do_handshake()) to not indicate success and a subsequent call to SSL_get_error() to return
  the value SSL_ERROR_WANT_RETRY_VERIFY. This return value is only supposed to be returned by
  OpenSSL if the application has previously called SSL_CTX_set_cert_verify_callback(). Since most
  applications do not do this the SSL_ERROR_WANT_RETRY_VERIFY return value from SSL_get_error()
  will be totally unexpected and applications may not behave correctly as a result. The exact
  behaviour will depend on the application but it could result in crashes, infinite loops or other
  similar incorrect responses.

  This issue is made more serious in combination with a separate bug in OpenSSL 3.0 that will cause
  X509_verify_cert() to indicate an internal error when processing a certificate chain. This will
  occur where a certificate does not include the Subject Alternative Name extension but where a
  Certificate Authority has enforced name constraints. This issue can occur even with valid chains.

  By combining the two issues an attacker could induce incorrect, application dependent behaviour.");

  script_tag(name:"affected", value:"OpenSSL 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20211214.txt");

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

if (version_is_equal(version: version, test_version: "3.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
