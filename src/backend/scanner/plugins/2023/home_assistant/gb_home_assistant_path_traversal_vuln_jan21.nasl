# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:home-assistant:home-assistant";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170487");
  script_version("2023-06-16T14:09:42+0000");
  script_tag(name:"last_modification", value:"2023-06-16 14:09:42 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 09:34:42 +0000 (Thu, 15 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 16:35:00 +0000 (Tue, 02 Feb 2021)");

  script_cve_id("CVE-2021-3152");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Only vulnerable if using custom integrations, which we do not detect

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Home Assistant < 2021.1.3 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_home_assistant_consolidation.nasl");
  script_mandatory_keys("home_assistant/detected");

  script_tag(name:"summary", value:"Home Assistant instances using custom integrations are prone to a
  path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Home Assistant does not have a protection layer that can help to
  prevent directory-traversal attacks against custom integrations.");

  script_tag(name:"affected", value:"Home Assistant prior to version 2021.1.3.");

  script_tag(name:"solution", value:"Update to version 2021.1.3 or later.

  Note: Vendor states that only instances using custom integrations are vulnerable.");

  script_xref(name:"URL", value:"https://www.home-assistant.io/blog/2021/01/22/security-disclosure/");
  script_xref(name:"URL", value:"https://www.home-assistant.io/blog/2021/01/14/security-bulletin/");

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

if ( version_is_less( version:version, test_version:"2021.1.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2021.1.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
