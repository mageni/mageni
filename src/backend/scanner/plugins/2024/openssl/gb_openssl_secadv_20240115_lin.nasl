# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114276");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-15 13:00:32 +0000 (Mon, 15 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-6237");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20240115) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Applications that use the function EVP_PKEY_public_check() to
  check RSA public keys may experience long delays.");

  script_tag(name:"impact", value:"Where the key that is being checked has been obtained from an
  untrusted source this may lead to a DoS.");

  script_tag(name:"affected", value:"OpenSSL versions 3.0, 3.1 and 3.2.");

  script_tag(name:"solution", value:"Update to version 3.0.13, 3.1.5, 3.2.1 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240115.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.0", test_version_up: "3.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
