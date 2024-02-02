# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126562");
  script_version("2024-01-25T05:06:22+0000");
  script_tag(name:"last_modification", value:"2024-01-25 05:06:22 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-23 11:49:00 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-18 19:47:00 +0000 (Thu, 18 Jan 2024)");

  script_cve_id("CVE-2023-51790");

  # nb: Currently not fully clear if the relevant "Admin Tools" plugin-in from here can / needs to
  # be separately installed: https://piwigo.org/ext/extension_view.php?eid=720
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 14.1.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to a cross-site scripting (XSS)
  vulnerability in the Admin Tools plug-in component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote attacker could obtain sensitive information via the
  lang parameter in the Admin Tools plug-in component.");

  script_tag(name:"affected", value:"Piwigo prior to version 14.1.0.");

  script_tag(name:"solution", value:"Update to version 14.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/AdminTools/issues/21");
  script_xref(name:"URL", value:"https://github.com/Piwigo/AdminTools/commit/980e3ee17cf67029732681347aa320c2e9aa8a3c");
  script_xref(name:"URL", value:"https://github.com/Hebing123/cve/issues/6");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "14.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
