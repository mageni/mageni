# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124332");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-01 08:30:56 +0200 (Thu, 01 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:P/A:C");

  script_cve_id("CVE-2023-2998", "CVE-2023-2999");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.1.14 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2998: Stored XSS in FAQ News module

  - CVE-2023-2999: Stored XSS in 'Add new FAQ' feature");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.14.");

  script_tag(name:"solution", value:"Update to version 3.1.14 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/8282d78e-f399-4bf4-8403-f39103a31e78/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4d89c7cc-fb4c-4b64-9b67-f0189f70a620/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.14");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
