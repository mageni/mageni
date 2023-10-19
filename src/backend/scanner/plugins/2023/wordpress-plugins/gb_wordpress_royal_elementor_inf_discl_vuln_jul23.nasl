# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:royal-elementor-addons:royal_elementor_addons";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127499");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-24 07:14:31 +0200 (Mon, 24 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-18 03:15:00 +0000 (Tue, 18 Jul 2023)");

  script_cve_id("CVE-2023-3709");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Royal Elementor Addons Plugin < 1.3.71 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/royal-elementor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Royal Elementor Addons' is prone to
  an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker is able to obtain a site's MailChimp API key.");

  script_tag(name:"affected", value:"WordPress The Royal Elementor Addons plugin prior to
  version 1.3.71.");

  script_tag(name:"solution", value:"Update to version 1.3.71 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/86c9bcf1-c69e-47ca-b74b-8ce6157f520b");

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

if( version_is_less( version: version, test_version: "1.3.71" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.71", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
