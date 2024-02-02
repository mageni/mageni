# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124462");
  script_version("2023-11-30T05:06:26+0000");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 12:10:52 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 18:06:00 +0000 (Thu, 02 Nov 2023)");

  script_cve_id("CVE-2023-45134", "CVE-2023-45135", "CVE-2023-45137");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 14.10.12, 15.0-rc-1 < 15.5-rc-1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45134: An attacker can create a template provider on any document that is part of the
  wiki (could be the attacker's user profile) that contains malicious code.

  - CVE-2023-45135: In XWiki, it is possible to pass a title to the page creation action that isn't
  displayed at first but then executed in the second step.

  - CVE-2023-45137: When trying to create a document that already exists, XWiki
  displays an error message in the form for creating it. Due to missing escaping, this error
  message is vulnerable to raw HTML injection and thus XSS.");

  script_tag(name:"affected", value:"XWiki version prior to 14.10.12, 15.0-rc-1 prior to
  15.5-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.10.12, 15.5-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-gr82-8fj2-ggc3");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-ghf6-2f42-mjh9");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-93gh-jgjj-r929");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "14.10.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.10.12", install_path: location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
