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
  script_oid("1.3.6.1.4.1.25623.1.0.112980");
  script_version("2021-08-25T07:30:10+0000");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-25 07:05:11 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-3711");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: SM2 Decryption Buffer Overflow (20210824) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In order to decrypt SM2 encrypted data an application is
  expected to call the API function EVP_PKEY_decrypt(). Typically an application will call this
  function twice. The first time, on entry, the 'out' parameter can be NULL and,
  on exit, the 'outlen' parameter is populated with the buffer size required to
  hold the decrypted plaintext. The application can then allocate a sufficiently
  sized buffer and call EVP_PKEY_decrypt() again, but this time passing a non-NULL
  value for the 'out' parameter.

  A bug in the implementation of the SM2 decryption code means that the
  calculation of the buffer size required to hold the plaintext returned by the
  first call to EVP_PKEY_decrypt() can be smaller than the actual size required by
  the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is
  called by the application a second time with a buffer that is too small.");

  script_tag(name:"impact", value:"A malicious attacker who is able present SM2 content for
  decryption to an application could cause attacker chosen data to overflow the buffer by up to a
  maximum of 62 bytes altering the contents of other data held after the
  buffer, possibly changing application behaviour or causing the application to
  crash. The location of the buffer is application dependent but is typically
  heap allocated.");

  script_tag(name:"affected", value:"OpenSSL 1.1.1 through 1.1.1k.");

  script_tag(name:"solution", value:"Update to version 1.1.1l or later.");

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

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1k")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1l", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
