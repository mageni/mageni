# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netatalk_project:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124500");
  script_version("2023-09-22T16:08:59+0000");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-22 07:58:13 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-42464");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netatalk 3.1.x < 3.1.17 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When parsing Spotlight RPC packets, one encoded data structure
  is a key-value style dictionary where the keys are character strings, and the values can be any
  of the supported types in the underlying protocol. Due to a lack of type checking in callers of
  the dalloc_value_for_key() function, which returns the object associated with a key, a malicious
  actor may be able to fully control the value of the pointer and theoretically achieve remote code
  execution on the host.");

  script_tag(name:"impact", value:"This vulnerability allows remote attackers to execute arbitrary
  code on affected installations of Netatalk. Authentication is not required to exploit this
  vulnerability.");

  script_tag(name:"affected", value:"Netatalk version 3.1.x prior to 3.1.17.");

  script_tag(name:"solution", value:"Update to version 3.1.17 or later.");

  script_xref(name:"URL", value:"https://github.com/Netatalk/netatalk/issues/486");

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

if( version_in_range_exclusive( version: version, test_version_lo: "3.1.0", test_version_up: "3.1.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.17", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
