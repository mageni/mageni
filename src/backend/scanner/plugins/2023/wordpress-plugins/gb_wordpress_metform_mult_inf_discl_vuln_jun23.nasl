# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpmet:metform_elementor_contact_form_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127471");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-16 07:12:39 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-14 20:25:00 +0000 (Wed, 14 Jun 2023)");

  script_cve_id("CVE-2023-0688", "CVE-2023-0691", "CVE-2023-0692", "CVE-2023-0693",
                "CVE-2023-0694");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Metform Elementor Contact Form Builder Plugin < 3.3.2 Multiple Information Disclosure Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/metform/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Metform Elementor Contact Form Builder'
  is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0688: There is an authenticated information disclosure via the 'mf_thankyou'
  shortcode.

  - CVE-2023-0691: There is an authenticated information disclosure via the 'mf_last_name'
  shortcode.

  - CVE-2023-0692: There is an authenticated information disclosure via the 'mf_payment_status'
  shortcode.

  - CVE-2023-0693: There is an authenticated information disclosure via 'mf_transaction_id'
  shortcode.

  - CVE-2023-0694: There is an authenticated information disclosure via 'mf' shortcode.");

  script_tag(name:"affected", value:"WordPress Metform Elementor Contact Form Builder plugin prior
  to version 3.3.2.");

  script_tag(name:"solution", value:"Update to version 3.3.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/81fc41a4-9206-404c-bd5b-821c77ff3593");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/8fc4b815-dc05-4270-bf7a-3b01622739d7");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/ddd85ff2-6607-4ac8-b91c-88f6f2fa6c56");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1f33a8db-7cd0-4a53-b2c1-cd5b7cd16214");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1a8b194c-371f-4adc-98fa-8f4e47a38ee7");

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

if( version_is_less( version: version, test_version: "3.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.2", install_path: location );
  security_message( port: port, data: report);
  exit( 0 );
}

exit( 99 );
