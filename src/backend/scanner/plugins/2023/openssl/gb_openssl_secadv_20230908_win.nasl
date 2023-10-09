# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104902");
  script_version("2023-09-08T16:09:14+0000");
  script_tag(name:"last_modification", value:"2023-09-08 16:09:14 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-08 13:21:45 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2023-4807");

  # nb: Only specific environments are affected, see the affected tag.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL Security Vulnerability (20230908) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The POLY1305 MAC (message authentication code) implementation
  contains a bug that might corrupt the internal state of applications.");

  script_tag(name:"impact", value:"If in an application that uses the OpenSSL library an attacker
  can influence whether the POLY1305 MAC algorithm is used, the application state might be corrupted
  with various application dependent consequences.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.1 to 1.1.1v, 3.0.0 to 3.0.10, and 3.1.0 to
  3.1.2 are vulnerable to this issue.

  Notes:

  - The FIPS provider is not affected because the POLY1305 MAC algorithm is not FIPS approved and
  the FIPS provider does not implement it.

  - OpenSSL version 1.0.2 is not affected by this issue.

  - This flaw only affects the Windows 64 platform and only when running on newer X86_64 processors
  supporting the AVX512-IFMA instructions.");

  script_tag(name:"solution", value:"No known solution is available as of 08th September, 2023.
  Information regarding this issue will be updated once solution details are available.

  Vendor info: Due to the low severity of this issue we are not issuing new releases of OpenSSL at
  this time. The fix will be included in the next releases when they become available. The fix is
  also available in commit 4bfac447 (for 3.1), commit 6754de4a (for 3.0), and commit a632d534 (for
  1.1.1) in the OpenSSL git repository.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230908.txt");

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

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1v")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99); # nb: We can use exit(99); here since other versions like 1.0.2 are not affected
