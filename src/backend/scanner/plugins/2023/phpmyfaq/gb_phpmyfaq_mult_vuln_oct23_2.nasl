# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124457");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-02 09:08:56 +0200 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 18:09:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2023-5864", "CVE-2023-5866");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5864: Stored cross-site scripting (XSS) in FAQ

  - CVE-2023-5866: Sensitive cookie in HTTPS session without 'Secure' attribute.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.1 or later.");

  script_xref(name:"URL", value:"https://huntr.com/bounties/e4b0e8f4-5e06-49d1-832f-5756573623ad/");
  script_xref(name:"URL", value:"https://huntr.com/bounties/ec44bcba-ae7f-497a-851e-8165ecf56945/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if (!version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if ( version_is_less( version: version, test_version: "3.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
