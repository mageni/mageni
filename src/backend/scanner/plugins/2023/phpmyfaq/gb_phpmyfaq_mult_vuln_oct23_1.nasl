# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124456");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-02 09:08:56 +0200 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 19:55:00 +0000 (Thu, 09 Nov 2023)");

  script_cve_id("CVE-2023-5863", "CVE-2023-5865", "CVE-2023-5867");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5863: Reflected cross-site scripting (XSS)

  - CVE-2023-5865: Insufficient session expiration

  - CVE-2023-5867: Stored cross-site scripting (XSS) in attachment file name");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.2.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_xref(name:"URL", value:"https://huntr.com/bounties/fbfd4e84-61fb-4063-8f11-15877b8c1f6f/");
  script_xref(name:"URL", value:"https://huntr.com/bounties/4c4b7395-d9fd-4ca0-98d7-2e20c1249aff/");
  script_xref(name:"URL", value:"https://huntr.com/bounties/5c09b32e-a041-4a1e-a277-eb3e80967df0/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if (!version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if ( version_is_less( version: version, test_version: "3.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
