# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:royal-elementor-addons:royal_elementor_addons";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126360");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 13:14:31 +0200 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 19:32:00 +0000 (Fri, 13 Jan 2023)");

  script_cve_id("CVE-2022-4102", "CVE-2022-4103");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Royal Elementor Addons Plugin < 1.3.56 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/royal-elementor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Royal Elementor Addons' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4102: Lack of authorization and CSRF checks when deleting a template and does not
  ensure that the post to be deleted is a template.

  - CVE-2022-4103: Lack of authorization and CSRF checks when creating a template, and does not
  ensure that the post created is a template.");

  script_tag(name:"affected", value:"WordPress The Royal Elementor Addons plugin prior to
  version 1.3.56.");

  script_tag(name:"solution", value:"Update to version 1.3.56 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c177f763-0bb5-4734-ba2e-7ba816578937");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5e1244f7-39b5-4f37-8fef-e3f35fc388f1");

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

if( version_is_less( version: version, test_version: "1.3.56" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.56", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
