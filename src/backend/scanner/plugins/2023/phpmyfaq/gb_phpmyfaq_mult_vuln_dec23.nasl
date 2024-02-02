# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124493");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-20 08:08:56 +0200 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-19 13:50:00 +0000 (Tue, 19 Dec 2023)");

  script_cve_id("CVE-2023-6889", "CVE-2023-6890");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.1.17 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6889: Stored XSS Bypass in the TAGS Section and other places in the application.

  - CVE-2023-6890: Stored XSS Bypass in the FAQ Fields.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.17.");

  script_tag(name:"solution", value:"Update to version 3.1.17 or later.");

  script_xref(name:"URL", value:"https://huntr.com/bounties/52897778-fad7-4169-bf04-a68a0646df0c");
  script_xref(name:"URL", value:"https://huntr.com/bounties/2cf11678-8793-4fa1-b21a-f135564a105d");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if (!version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if ( version_is_less( version: version, test_version: "3.1.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.17" );
  security_message( data: report, port: port );
  exit(0);
}

exit( 99 );
