# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:getshortcodes:shortcodes_ultimate";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127644");
  script_version("2024-01-24T05:06:24+0000");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-11-29 08:40:51 +0000 (Wed, 29 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 15:10:00 +0000 (Mon, 04 Dec 2023)");

  script_cve_id("CVE-2023-6225", "CVE-2023-6226");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Shortcodes Ultimate Plugin < 7.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/shortcodes-ultimate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Shortcodes Ultimate' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6225: Authenticated attackers are able to inject arbitrary web scripts in pages that
  will execute whenever a user accesses an injected page due to insufficient input sanitization and
  output escaping on user supplied meta values.

  - CVE-2023-6226: Authenticated attackers are able to retrieve arbitrary post meta values which
  may contain sensitive information due to missing validation on the user controlled keys 'key' and
  'post_id' in the su_meta shortcode.");

  script_tag(name:"affected", value:"WordPress Shortcodes Ultimate plugin prior to version 7.0.0.");

  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/558e36f6-4678-46a2-8154-42770fbb5574");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/4d936a48-b300-4a41-8d28-ba34cb3c5cb7");

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

if( version_is_less( version: version, test_version: "7.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
