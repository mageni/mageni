# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124498");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-27 09:30:39 +0000 (Wed, 27 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 20:50:00 +0000 (Wed, 29 Nov 2023)");

  script_cve_id("CVE-2023-48240");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 11.10.1 < 14.10.15, 15.x < 15.5.1 SSRF Vulnerability (GHSA-7rfg-6273-f5wp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a server side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The rendered diff in XWiki embeds images to be able to compare
  the contents and not display a difference for an actually unchanged image. For this, XWiki
  requests all embedded images on the server side. These requests are also sent for images from
  other domains and include all cookies that were sent in the original request to ensure that
  images with restricted view right can be compared.");

  script_tag(name:"affected", value:"XWiki version 11.10.1 prior to 14.10.15, 15.x prior to 15.5.1.");

  script_tag(name:"solution", value:"Update to version 14.10.15, 15.5.1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-7rfg-6273-f5wp");

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

if( version_in_range_exclusive( version:version, test_version_lo:"11.10.1", test_version_up:"14.10.15" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.15", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0", test_version_up:"15.5.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
