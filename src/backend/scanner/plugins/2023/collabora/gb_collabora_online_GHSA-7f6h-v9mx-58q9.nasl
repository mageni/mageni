# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:collabora:online";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104759");
  script_version("2023-05-24T09:09:06+0000");
  script_cve_id("CVE-2021-43817");
  script_tag(name:"last_modification", value:"2023-05-24 09:09:06 +0000 (Wed, 24 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-23 08:50:37 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-15 21:59:00 +0000 (Wed, 15 Dec 2021)");
  script_name("Collabora CODE / Collabora Online < 4.2.20 / 5.x < 6.4.16 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_collabora_libreoffice_online_http_detect.nasl");
  script_mandatory_keys("collabora_libreoffice/online/detected");

  script_xref(name:"URL", value:"https://github.com/CollaboraOnline/online/security/advisories/GHSA-7f6h-v9mx-58q9");

  script_tag(name:"summary", value:"Collabora CODE (Collabora Online Development Edition) and
  Collabora Online are prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A reflected XSS vulnerability was found in Collabora Online. An
  attacker could inject unescaped HTML into a variable as they created the Collabora Online iframe,
  and execute scripts inside the context of the Collabora Online iframe. This would give access to a
  small set of user settings stored in the browser, as well as the session's authentication token
  which was also passed in at iframe creation time.");

  script_tag(name:"affected", value:"Collabora CODE / Collabora Online versions prior to 4.2.20 and
  5.x/6.x prior to 6.4.16.");

  script_tag(name:"solution", value:"Update to version 4.2.20, 6.4.16 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.2.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.2.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"5.0", test_version_up:"6.4.16" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.4.16", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
