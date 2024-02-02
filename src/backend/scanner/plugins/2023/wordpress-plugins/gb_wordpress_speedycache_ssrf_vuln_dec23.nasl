# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:softaculous:speedycache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124489");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 07:35:51 +0200 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 16:56:00 +0000 (Tue, 12 Dec 2023)");

  script_cve_id("CVE-2023-49746");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SpeedyCache Plugin < 1.1.3 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/speedycache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SpeedyCache' is prone to a server-side
  request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This could allow a malicious actor to cause a website to
  execute website requests to an arbitrary domain of the attacker.");

  script_tag(name:"affected", value:"WordPress SpeedyCache plugin prior to version 1.1.3.");

  script_tag(name:"solution", value:"Update to version 1.1.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/speedycache/wordpress-speedycache-plugin-1-1-2-server-side-request-forgery-ssrf-vulnerability");


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

if( version_is_less( version: version, test_version: "1.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
