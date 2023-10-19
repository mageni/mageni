# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_blocks";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124337");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 07:44:07 +0000 (Thu, 15 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-15 18:41:00 +0000 (Thu, 15 Jun 2023)");

  script_cve_id("CVE-2023-2083", "CVE-2023-2084", "CVE-2023-2085", "CVE-2023-2086", "CVE-2023-2087");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Blocks Plugin < 4.0.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-blocks/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Blocks' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2083: Missing Authorization via save.

  - CVE-2023-2084: Missing Authorization via get.

  - CVE-2023-2085: Missing Authorization via templates.

  - CVE-2023-2086: Missing Authorization via template_count.

  - CVE-2023-2087: Cross-Site Request Forgery (CSRF) via save");

  script_tag(name:"affected", value:"WordPress Essential Blocks plugin prior to version 4.0.7.");

  script_tag(name:"solution", value:"Update to version 4.0.7 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-blocks/essential-blocks-406-missing-authorization-via-save");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-blocks/essential-blocks-406-cross-site-request-forgery-via-save");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-blocks/essential-blocks-406-missing-authorization-via-template-count");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-blocks/essential-blocks-406-missing-authorization-via-templates");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-blocks/essential-blocks-406-missing-authorization-via-get");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
