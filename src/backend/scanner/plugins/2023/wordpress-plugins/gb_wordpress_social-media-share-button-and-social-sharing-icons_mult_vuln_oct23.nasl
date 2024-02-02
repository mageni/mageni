# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ultimatelysocial:social_media_share_buttons_%26_social_sharing_icons";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127598");
  script_version("2023-11-01T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-11-01 05:05:34 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 08:00:00 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-30 11:18:00 +0000 (Mon, 30 Oct 2023)");

  script_cve_id("CVE-2023-5070", "CVE-2023-5602");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Social Media Share Buttons & Social Sharing Icons Plugin < 2.8.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-social-media-icons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Social Media Share Buttons & Social
  Sharing Icons' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5070: Attackers are able to export plugin settings that include social media
  authentication tokens and secrets as well as app passwords.

  - CVE-2023-5602: Attackers are able to invoke AJAX actions via a forged request granted due to
  missing or incorrect nonce validation on several functions.");

  script_tag(name:"affected", value:"WordPress Social Media Share Buttons & Social Sharing Icons
  plugin prior to version 2.8.6.");

  script_tag(name:"solution", value:"Update to version 2.8.6 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/e9e43c5b-a094-44ab-a8a3-52d437f0e00d");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/d44a45fb-3bff-4a1f-8319-a58a47a9d76b");

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

if( version_is_less( version: version, test_version: "2.8.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
