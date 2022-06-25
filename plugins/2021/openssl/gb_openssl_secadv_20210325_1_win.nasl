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
  script_oid("1.3.6.1.4.1.25623.1.0.145655");
  script_version("2021-03-26T06:50:49+0000");
  script_tag(name:"last_modification", value:"2021-03-26 11:26:30 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-26 02:17:02 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-3450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: CA Certificate Check Bypass Vulnerability (CVE-2021-3450) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a CA certificate check bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The X509_V_FLAG_X509_STRICT flag enables additional
  security checks of the certificates present in a certificate chain. It is not set
  by default.

  Starting from OpenSSL version 1.1.1h a check to disallow certificates in
  the chain that have explicitly encoded elliptic curve parameters was added
  as an additional strict check.

  An error in the implementation of this check meant that the result of a
  previous check to confirm that certificates in the chain are valid CA
  certificates was overwritten. This effectively bypasses the check
  that non-CA certificates must not be able to issue other certificates.

  If a 'purpose' has been configured then there is a subsequent opportunity
  for checks that the certificate is a valid CA. All of the named 'purpose'
  values implemented in libcrypto perform this check. Therefore, where
  a purpose is set the certificate chain will still be rejected even when the
  strict flag has been used. A purpose is set by default in libssl client and
  server certificate verification routines, but it can be overridden or
  removed by an application.

  In order to be affected, an application must explicitly set the
  X509_V_FLAG_X509_STRICT verification flag and either not set a purpose
  for the certificate verification or, in the case of TLS client or server
  applications, override the default purpose.");

  script_tag(name:"affected", value:"OpenSSL version 1.1.1h through 1.1.1j.");

  script_tag(name:"solution", value:"Update OpenSSL to version 1.1.1k or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210325.txt");

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

if (version_in_range(version: version, test_version: "1.1.1h", test_version2: "1.1.1j")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1k", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
