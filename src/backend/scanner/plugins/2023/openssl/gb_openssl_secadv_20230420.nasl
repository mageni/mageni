# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104696");
  script_version("2023-04-24T10:19:26+0000");
  script_tag(name:"last_modification", value:"2023-04-24 10:19:26 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 11:32:48 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-1255");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Only  64 bit ARM platform affected

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL 3.0 <= 3.0.8, 3.1.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The AES-XTS cipher decryption implementation for 64 bit ARM
  platform contains a bug that could cause it to read past the input buffer, leading to a crash.");

  script_tag(name:"impact", value:"Applications that use the AES-XTS algorithm on the 64 bit ARM
  platform can crash in rare circumstances. The AES-XTS algorithm is usually used for disk
  encryption.

  The AES-XTS cipher decryption implementation for 64 bit ARM platform will read past the end of the
  ciphertext buffer if the ciphertext size is 4 mod 5 in 16 byte blocks, e.g. 144 bytes or 1024
  bytes. If the memory after the ciphertext buffer is unmapped, this will trigger a crash which
  results in a denial of service.

  If an attacker can control the size and location of the ciphertext buffer being decrypted by an
  application using AES-XTS on 64 bit ARM, the application is affected. This is fairly unlikely
  making this issue a Low severity one.");

  script_tag(name:"affected", value:"OpenSSL versions 3.0.0 through 3.0.8 and 3.1.0 on 64 bit ARM
  platforms.");

  script_tag(name:"solution", value:"No known solution is available as of 21st April, 2023.
  Information regarding this issue will be updated once solution details are available.

  Note: Due to the low severity of this issue the vendor is not issuing new releases of OpenSSL at
  this time. The fix will be included in the next releases when they become available. The fix is
  also available in commit bc2f61ad (for 3.1) and commit 02ac9c94 (for 3.0) in the OpenSSL git
  repository.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230420.txt");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
