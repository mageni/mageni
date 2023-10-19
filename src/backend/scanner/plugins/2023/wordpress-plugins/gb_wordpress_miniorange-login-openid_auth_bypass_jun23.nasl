# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:miniorange:wordpress_social_login_and_register_%28discord%2c_google%2c_twitter%2c_linkedin%29";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124344");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-29 09:11:03 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-29 02:15:00 +0000 (Thu, 29 Jun 2023)");

  script_cve_id("CVE-2023-2982");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Social Login and Register < 7.6.5 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/miniorange-login-openid/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Social Login and Register' is prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This is due to insufficient encryption on the user being supplied
  during a login validated through the plugin. This makes it possible for unauthenticated attackers
  to log in as any existing user on the site, such as an administrator, if they know the email
  address associated with that user.");

  script_tag(name:"affected", value:"WordPress Social Login and Register plugin prior to version 7.6.5.");

  script_tag(name:"solution", value:"Update to version 7.6.5 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/miniorange-login-openid/wordpress-social-login-and-register-discord-google-twitter-linkedin-764-authentication-bypass");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"7.6.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.6.5", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

