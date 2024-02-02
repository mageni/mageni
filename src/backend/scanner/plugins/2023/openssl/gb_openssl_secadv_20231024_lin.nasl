# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170621");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 11:03:11 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 13:55:00 +0000 (Thu, 09 Nov 2023)");

  script_cve_id("CVE-2023-5363");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Incorrect Cipher Key & IV Length Processing Vulnerability (20231024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to an incorrect processing of key and
  initialisation vector (IV) lengths vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or
  EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been
  established. Any alterations to the key length, via the 'keylen' parameter or the IV length, via
  the 'ivlen' parameter, within the OSSL_PARAM array will not take effect as intended, potentially
  causing truncation or overreading of these values. The following ciphers and cipher modes are
  impacted: RC2, RC4, RC5, CCM, GCM and OCB.");

  script_tag(name:"impact", value:"A truncation in the IV can result in non-uniqueness, which could
  result in loss of confidentiality for some cipher modes.");

  script_tag(name:"affected", value:"OpenSSL version 3.0 and 3.1.");

  script_tag(name:"solution", value:"Update to version 3.0.12, 3.1.4 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20231024.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-3.0.html#CVE-2023-5363");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-3.1.html#CVE-2023-5363");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.0", test_version_up: "3.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
