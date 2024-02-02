# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpexperts:post_smtp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126547");
  script_version("2023-12-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-12-05 05:06:18 +0000 (Tue, 05 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-28 10:32:43 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-02 04:36:00 +0000 (Sat, 02 Dec 2023)");

  script_cve_id("CVE-2023-5958");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Post SMTP Mailer/Email Log Plugin < 2.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/post-smtp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Post SMTP Mailer/Email Log' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape email message content before
  displaying it in the backend, allowing an unauthenticated attacker to perform XSS attacks against
  highly privileged users.");

  script_tag(name:"affected", value:"WordPress Post SMTP Mailer/Email Log plugin prior to
  version 2.7.1.");

  script_tag(name:"solution", value:"Update to version 2.7.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/22fa478d-e42e-488d-9b4b-a8720dec7cee/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"2.7.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );