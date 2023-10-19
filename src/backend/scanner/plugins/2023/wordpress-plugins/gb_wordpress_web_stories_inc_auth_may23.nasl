# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:web_stories";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126293");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-17 09:11:03 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-12 18:44:00 +0000 (Fri, 12 May 2023)");

  script_cve_id("CVE-2023-1979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Web Stories Plugin < 1.32 Incorrect Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/web-stories/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Web Stories' is prone to an incorrect
  authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users with the 'Author' role can create stories, but don't have
  the ability to edit password protected stories. The vulnerability allowed users with said role to
  bypass this permission check when trying to duplicate the protected story in the plugin's own
  dashboard, giving them access to the seemingly protected content.");

  script_tag(name:"affected", value:"WordPress Web Stories plugin prior to version 1.32.");

  script_tag(name:"solution", value:"Update to version 1.32 or later.");

  script_xref(name:"URL", value:"https://github.com/GoogleForCreators/web-stories-wp/releases/tag/v1.32.0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.32" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.32", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

