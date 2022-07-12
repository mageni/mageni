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
  script_oid("1.3.6.1.4.1.25623.1.0.112939");
  script_version("2021-08-13T14:30:27+0000");
  script_tag(name:"last_modification", value:"2021-08-16 10:18:22 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1387",
                "CVE-2009-3245", "CVE-2009-3555", "CVE-2009-4355");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Multiple Vulnerabilities (0.9.8 - 0.9.8l) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple denial of service flaws in the DTLS implementation (CVE-2009-1377, CVE-2009-1378,
  CVE-2009-1387)

  - Use-after-free vulnerability in the dtls1_retrieve_buffered_fragment function could cause a
  client accessing a malicious DTLS server to crash (CVE-2009-1379)

  - It was discovered that OpenSSL did not always check the return value of the bn_wexpand()
  function. An attacker able to trigger a memory allocation failure in that function could cause an
  application using the OpenSSL library to crash or, possibly, execute arbitrary code (CVE-2009-3245)

  - A Man-in-the-middle renegotiation attack (CVE-2009-3555)

  - A memory leak in the zlib_stateful_finish function in crypto/comp/c_zlib.c allows remote
  attackers to cause a denial of service via vectors that trigger incorrect calls to the
  CRYPTO_cleanup_all_ex_data function (CVE-2009-4355)");

  script_tag(name:"affected", value:"OpenSSL 0.9.8 through 0.9.8l.");

  script_tag(name:"solution", value:"Update to version 0.9.8m or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20100710092848/https://rt.openssl.org/Ticket/Display.html?id=1838");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/7e4cae1d2f555cbe9226b377aff4b56c9f7ddd4d");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/1b31b5ad560b16e2fe1cad54a755e3e6b5e778a3");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120306065500/http://rt.openssl.org/Ticket/Display.html?id=1930&user=guest&pass=guest");
  script_xref(name:"URL", value:"https://web.archive.org/web/20101120211136/http://rt.openssl.org/Ticket/Display.html?id=1931&user=guest&pass=guest");
  script_xref(name:"URL", value:"https://web.archive.org/web/20100824233642/http://rt.openssl.org/Ticket/Display.html?id=1923&user=guest&pass=guest");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20091111.txt");

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

if (version_in_range(version: version, test_version: "0.9.8", test_version2: "0.9.8l")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8m", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
