# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yithemes:yith_woocommerce_gift_cards";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127535");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-30 07:38:12 +0000 (Wed, 30 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-07 21:50:00 +0000 (Wed, 07 Dec 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-45359");

  script_name("WordPress YITH WooCommerce Gift Cards Premium Plugin < 3.20.0 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/yith-woocommerce-gift-cards-premium/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'YITH WooCommerce Gift Cards Premium' is
  prone to an arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate files to be uploaded, allowing
  unauthenticated attackers to upload arbitrary files, such as PHP.");

  script_tag(name:"affected", value:"WordPress YITH WooCommerce Gift Cards Premium plugin prior to
  version 3.20.0.");

  script_tag(name:"solution", value:"Update to version 3.20.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e8f8bdc0-ac53-4b14-b34c-4930076711ce");

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

if( version_is_less( version: version, test_version: "3.20.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.20.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
