# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:home-assistant:home-assistant";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170486");
  script_version("2023-06-16T14:09:42+0000");
  script_tag(name:"last_modification", value:"2023-06-16 14:09:42 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 09:34:42 +0000 (Thu, 15 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 19:46:00 +0000 (Mon, 14 Mar 2022)");

  script_cve_id("CVE-2020-36517");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Current detection does not distinguish between Supervised and other installation types

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Home Assistant Information Disclosure Vulnerability (Mar 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_home_assistant_consolidation.nasl");
  script_mandatory_keys("home_assistant/detected");

  script_tag(name:"summary", value:"Home Assistant OS and Home Assistant Supervised are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information leak allows a DNS operator to gain knowledge about
  internal network resources via the hardcoded DNS resolver configuration.");

  script_tag(name:"affected", value:"Home Assistant OS and Home Assistant Supervised through version
  2023.6.2.");

  script_tag(name:"solution", value:"No known solution is available as of 16th June, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://community.home-assistant.io/t/ha-os-dns-setting-configuration-not-respected/356572/35");
  script_xref(name:"URL", value:"https://github.com/home-assistant/supervisor/pull/3586");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/issues/22");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/issues/50");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/issues/51");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/issues/53");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/issues/54");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/pull/86");
  script_xref(name:"URL", value:"https://github.com/home-assistant/plugin-dns/pull/87");

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

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );

