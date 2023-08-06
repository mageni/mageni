# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150799");
  script_version("2023-08-02T05:06:27+0000");
  script_tag(name:"last_modification", value:"2023-08-02 05:06:27 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-01 07:37:48 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-3817");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL DoS Vulnerability (20230731) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Checking excessively long DH keys or parameters may be very slow.");

  script_tag(name:"impact", value:"Applications that use the functions DH_check(), DH_check_ex() or
  EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays. Where the
  key or parameters that are being checked have been obtained from an untrusted source this may
  lead to a Denial of Service.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1, 3.0 and 3.1.");

  script_tag(name:"solution", value:"No known solution is available as of 01st August, 2023.
  Information regarding this issue will be updated once solution details are available.

  Vendor info: Due to the low severity of this issue we are not issuing new releases of OpenSSL at
  this time. The fix will be included in the next releases when they become available. The fix is
  also available in commit 6a1eb62c2 (for 3.1), commit 9002fd073 (for 3.0) and commit 91ddeba0f
  (for 1.1.1) in the OpenSSL git repository. It is available to premium support customer in commit
  869ad69a (for 1.0.2).");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230731.txt");

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

if (version =~ "^(1\.0\.2|1\.1\.1|3\.0|3\.1)") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99); # nb: We can use exit(99); here since other versions like 0.9.8 are not affected
