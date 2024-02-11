# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126594");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-06 09:08:56 +0200 (Tue, 06 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2024-22202", "CVE-2024-22208", "CVE-2024-24574");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.2.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-22202: PhpMyFAQ's user removal page allows an attacker to spoof another user's
  detail, and in turn make a compelling phishing case for removing another user's account.

  - CVE-2024-22208: The 'sharing FAQ' functionality allows any unauthenticated actor to misuse the
  phpMyFAQ application to send arbitrary emails to a large range of targets.

  - CVE-2024-24574: Unsafe echo of filename in phpMyFAQ\phpmyfaq\admin\attachments.php leading to
  allow execute JavaScript code in client side (XSS).");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.5.");

  script_tag(name:"solution", value:"Update to version 3.2.5 or later.");

  script_xref(name:"URL", value:"https://www.phpmyfaq.de/security/advisory-2024-02-05");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-6648-6g96-mg35");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-9hhf-xmcw-r3xg");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7m8g-fprr-47fx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "3.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
