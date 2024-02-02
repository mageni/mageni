# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:paidmembershipspro:paid_memberships_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127605");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-31 10:08:08 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 16:32:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2020-36754");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Paid Memberships Pro Plugin < 2.4.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/paid-memberships-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Paid Memberships Pro' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers are able to save pages via a forged request granted
  due to missing or incorrect nonce validation on the 'pmpro_page_save()' function.");

  script_tag(name:"affected", value:"WordPress Paid Memberships Pro plugin prior to version
  2.4.3.");

  script_tag(name:"solution", value:"Update to version 2.4.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/d74553a4-0ef7-4908-a2e8-5e0216f7b256");

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

if( version_is_less( version: version, test_version: "2.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
