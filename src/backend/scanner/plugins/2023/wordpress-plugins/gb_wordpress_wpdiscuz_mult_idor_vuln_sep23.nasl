# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gvectors:wpdiscuz";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127600");
  script_version("2023-10-27T16:11:33+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-26 08:00:00 +0000 (Thu, 26 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-26 14:59:00 +0000 (Thu, 26 Oct 2023)");

  script_cve_id("CVE-2023-3869", "CVE-2023-3998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress wpDiscuz Plugin < 7.6.4 Multiple IDOR Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wpdiscuz/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'wpDiscuz' is prone to multiple insecure
  direct object reference (IDOR) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-3869: Attackers are able to increase or decrease the rating of a comment due to
  missing authorization check on the voteOnComment function.

  - CVE-2023-3998: Attackers are able to increase or decrease the rating of a post due to missing
  authorization check on the userRate function.");

  script_tag(name:"affected", value:"WordPress wpDiscuz plugin prior to version 7.6.4.");

  script_tag(name:"solution", value:"Update to version 7.6.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/b30ac1b0-eae2-4194-bf8e-ae73b4236965");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/9d09bdab-ffab-44cc-bba2-821b21a8e343");

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

if( version_is_less( version: version, test_version: "7.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
