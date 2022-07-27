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
  script_oid("1.3.6.1.4.1.25623.1.0.112982");
  script_version("2021-08-25T07:30:10+0000");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-25 07:05:11 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2021-3712");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Read Buffer Overruns Processing ASN.1 Strings (20210824) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING
  structure which contains a buffer holding the string data and a field holding
  the buffer length. This contrasts with normal C strings which are represented as
  a buffer for the string data which is terminated with a NUL (0) byte.

  Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's
  own 'd2i' functions (and other similar parsing functions) as well as any string
  whose value has been set with the ASN1_STRING_set() function will additionally
  NUL terminate the byte array in the ASN1_STRING structure.

  However, it is possible for applications to directly construct valid ASN1_STRING
  structures which do not NUL terminate the byte array by directly setting the
  'data' and 'length' fields in the ASN1_STRING array. This can also happen by
  using the ASN1_STRING_set0() function.

  Numerous OpenSSL functions that print ASN.1 data have been found to assume that
  the ASN1_STRING byte array will be NUL terminated, even though this is not
  guaranteed for strings that have been directly constructed. Where an application
  requests an ASN.1 structure to be printed, and where that ASN.1 structure
  contains ASN1_STRINGs that have been directly constructed by the application
  without NUL terminating the 'data' field, then a read buffer overrun can occur.

  The same thing can also occur during name constraints processing of certificates
  (for example if a certificate has been directly constructed by the application
  instead of loading it via the OpenSSL parsing functions, and the certificate
  contains non NUL terminated ASN1_STRING structures). It can also occur in the
  X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions.");

  script_tag(name:"impact", value:"If a malicious actor can cause an application to directly construct an
  ASN1_STRING and then process it through one of the affected OpenSSL functions
  then this issue could be hit. This might result in a crash (causing a Denial of
  Service attack). It could also result in the disclosure of private memory
  contents (such as private keys, or sensitive plaintext).");

  script_tag(name:"affected", value:"OpenSSL 1.1.1 through 1.1.1k and 1.0.2 through 1.0.2y.

  Note: OpenSSL 1.0.2 is out of support and no longer receiving public updates. Extended
  support is available for premium support customers.");

  script_tag(name:"solution", value:"Update to version 1.0.2za, 1.1.1l or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210824.txt");

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

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2y")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2za / 1.1.1l", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1k")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1l", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
