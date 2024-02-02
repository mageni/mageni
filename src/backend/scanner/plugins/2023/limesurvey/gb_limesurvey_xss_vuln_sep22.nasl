# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127628");
  script_version("2023-11-28T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-11-28 05:05:32 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-20 08:19:19 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-25 01:22:00 +0000 (Sat, 25 Nov 2023)");

  script_cve_id("CVE-2023-44796");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 6.2.9-230925 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A regular user with 'theme' privileges who maliciously sets
  the 'templatename' during the importManifest process can lead to a stored cross-site
  scripting.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 6.2.9-230925.");

  script_tag(name:"solution", value:"Update to version 6.2.9-230925 or later.");

  script_xref(name:"URL", value:"https://github.com/Hebing123/CVE-2023-44796/issues/1");
  script_xref(name:"URL", value:"https://github.com/limesurvey/limesurvey/commit/135511073c51c332613dd7fad9a8ca0aad34a3fe");

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

if( version_is_less( version: version, test_version: "6.2.9-230925" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.9-230925", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
