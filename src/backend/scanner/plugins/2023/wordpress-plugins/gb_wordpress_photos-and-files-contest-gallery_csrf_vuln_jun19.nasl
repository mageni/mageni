# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:contest-gallery:contest_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127643");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-28 12:40:51 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-15 16:01:00 +0000 (Mon, 15 Jul 2019)");

  script_cve_id("CVE-2019-5974");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photos and Files Contest Gallery Plugin < 10.4.5 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/contest-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Photos and Files Contest Gallery' is
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers are able to hijack the authentication of
  administrators via unspecified vectors.");

  script_tag(name:"affected", value:"WordPress Photos and Files Contest Gallery plugin prior
  to version 10.4.5.");

  script_tag(name:"solution", value:"Update to version 10.4.5 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/contest-gallery/contest-gallery-photo-contest-plugin-for-wordpress-1044-cross-site-request-forgery");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "10.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
