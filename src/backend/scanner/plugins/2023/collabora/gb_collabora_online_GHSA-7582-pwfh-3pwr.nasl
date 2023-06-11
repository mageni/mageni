# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:collabora:online";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124333");
  script_version("2023-06-06T09:09:18+0000");
  script_tag(name:"last_modification", value:"2023-06-06 09:09:18 +0000 (Tue, 06 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-02 08:14:13 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-34088");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Collabora CODE / Collabora Online < 6.4.27, 21.x < 21.11.9.1, 22.x < 22.05.13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_collabora_libreoffice_online_http_detect.nasl");
  script_mandatory_keys("collabora_libreoffice/online/detected");

  script_tag(name:"summary", value:"Collabora CODE (Collabora Online Development Edition) and
  Collabora Online are prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored XSS vulnerability was found in Collabora Online. An
  attacker could create a document with an XSS payload as a document name. Later, if an
  administrator opens the admin console and navigates to the history page the document name is
  injected as unescaped HTML and executed as a script inside the context of the admin console. The
  administrator JWT used for the websocket connection can be leaked through this flaw.");

  script_tag(name:"affected", value:"Collabora CODE / Collabora Online versions prior to 6.4.27,
  21.x prior to 21.11.9.1 and 22.x prior to 22.05.13.");

  script_tag(name:"solution", value:"Update to version 6.4.27, 21.11.9.1, 22.05.13 or later.");

  script_xref(name:"URL", value:"https://github.com/CollaboraOnline/online/security/advisories/GHSA-7582-pwfh-3pwr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less(version: version, test_version: "6.4.27" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.27", install_path: location );
  security_message( port: port, data: report );
  exit(0);
}

if( version_in_range_exclusive( version:version, test_version_lo:"21.0", test_version_up:"21.11.9.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"21.11.9.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"22.0", test_version_up:"22.05.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"25.05.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
