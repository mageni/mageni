# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dir-300_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170476");
  script_version("2023-05-24T09:09:06+0000");
  script_tag(name:"last_modification", value:"2023-05-24 09:09:06 +0000 (Wed, 24 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-23 08:47:59 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-31814");

  script_name("D-Link DIR-300 Rev. A <= 1.06, Rev. B <= 2.06 File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-300 devices are prone to a file inclusion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A file inclusion is possible via /model/__lang_msg.php.");

  script_tag(name:"affected", value:"- D-Link DIR-300 Rev. A devices with firmware version 1.06 and
  prior

  - D-Link DIR-300 Rev. B devices with firmware version 2.06 and prior");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-300 Rev. Ax and Bx devices reached End-of-Support Date in 2010, they
  are no longer supported, and firmware development has ceased.");

  script_xref(name:"URL", value:"https://gist.github.com/1915504804/9503198d3cbd5bc7db47625ac0caaade");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! hw_version = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

if ( hw_version =~ "[AB]" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", extra:"Hardware revision: " + hw_version );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
