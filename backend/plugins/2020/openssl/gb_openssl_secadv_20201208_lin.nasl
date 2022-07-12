# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117063");
  script_version("2020-12-09T08:49:24+0000");
  script_tag(name:"last_modification", value:"2020-12-09 08:49:24 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 06:05:59 +0000 (Wed, 22 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-1971");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: EDIPARTYNAME NULL Pointer De-reference Vulnerability (CVE-2020-1971) (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial-of-Service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The X.509 GeneralName type is a generic type for representing different
  types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp
  which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves
  incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur
  leading to a possible denial of service attack.

  OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes:

  1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in
  an X509 certificate

  2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via
  the API functions TS_RESP_verify_response and TS_RESP_verify_token)

  If an attacker can control both items being compared then that attacker could trigger a crash. For example if
  the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then
  this may occur.

  Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking
  happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify
  tools have support for the '-crl_download' option which implements automatic CRL downloading and this attack has
  been demonstrated to work against those tools.

  Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
  EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and
  hence trigger this attack.");

  script_tag(name:"impact", value:"An attacker may trigger a crash and cause a DoS.");

  script_tag(name:"affected", value:"All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.

  OpenSSL 1.1.0 is out of support and no longer receiving updates of any kind. The impact of this issue on
  OpenSSL 1.1.0 has not been analysed.");

  script_tag(name:"solution", value:"OpenSSL 1.1.1 users should upgrade to 1.1.1i.

  OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2
  should upgrade to 1.0.2x. Other users should upgrade to OpenSSL 1.1.1i.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20201208.txt");

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

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2w")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2x / 1.1.1i", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.1\.0" || version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1h")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1i", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
