# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpmet:metform_elementor_contact_form_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127472");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-16 11:12:39 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-14 14:58:00 +0000 (Wed, 14 Jun 2023)");

  script_cve_id("CVE-2023-0695", "CVE-2023-0708", "CVE-2023-0709", "CVE-2023-0710",
                "CVE-2023-0721");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Metform Elementor Contact Form Builder Plugin < 3.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/metform/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Metform Elementor Contact Form Builder'
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0695: There is an authenticated stored cross-site scripting (XSS) via 'mf' shortcode.

  - CVE-2023-0708: There is an authenticated stored cross-site scripting (XSS) via 'mf_first_name'
  shortcode.

  - CVE-2023-0709: There is an authenticated stored cross-site scripting (XSS) via 'mf_last_name'
  shortcode.

  - CVE-2023-0710: There is an authenticated stored cross-site scripting (XSS) via 'mf_thankyou'
  shortcode.

  - CVE-2023-0721: There is an unauthenticated CSV injection.");

  script_tag(name:"affected", value:"WordPress Metform Elementor Contact Form Builder plugin prior
  to version 3.3.1.");

  script_tag(name:"solution", value:"Update to version 3.3.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1c866d8d-399c-4bda-a3c9-17c7e5d2ffb8");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/ae7549db-9a4b-4dee-8023-d7863dc3b4c8");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/25200656-a6a2-42f2-a607-26d4ff502cbf");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/89a98053-33c7-4e75-87a1-0f483a990641");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/ccd85a72-1872-4c4f-8ba7-7f91b0b37d4a");

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

if( version_is_less( version: version, test_version: "3.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.1", install_path: location );
  security_message( port: port, data: report);
  exit( 0 );
}

exit( 99 );
