# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124439");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-03 08:08:56 +0200 (Tue, 03 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-02 16:52:00 +0000 (Mon, 02 Oct 2023)");

  script_cve_id("CVE-2023-5227", "CVE-2023-5316", "CVE-2023-5317", "CVE-2023-5319", "CVE-2023-5320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.1.18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5227: File Upload in Categories

  - CVE-2023-5316: Stored XSS in Mail Setup

  - CVE-2023-5317: Stored XSS in FAQ Multisites

  - CVE-2023-5319: Stored XSS in Users

  - CVE-2023-5320: Stored DOM XSS in Edit configuration");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.18.");

  script_tag(name:"solution", value:"Update to version 3.1.18 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/a335c013-db75-4120-872c-42059c7100e8/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f877e65a-e647-457b-b105-7e5c9f58fb43/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/5e146e7c-60c7-498b-9ffe-fd4cb4ca8c54/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e2542cbe-41ab-4a90-b6a4-191884c1834d/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/3a2bc18b-5932-4fb5-a01e-24b2b0443b67/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if (!version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if ( version_is_less( version: version, test_version: "3.1.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.18" );
  security_message( data: report, port: port );
  exit(0);
}

exit( 99 );
