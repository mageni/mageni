# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:d-link:dap-1320_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170423");
  script_version("2023-04-20T08:00:36+0000");
  script_tag(name:"last_modification", value:"2023-04-20 08:00:36 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 20:06:18 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # 1.21b05 not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2050");

  script_name("D-Link DAP-1320 < 1.21b05 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1320 devices are prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"D-Link DAP-1320 devices prior to firmware version 1.21b05.");

  script_tag(name:"solution", value:"Update to firmware version 1.21b05 or later.

  Note: Vendor states that DAP-1320 model reached its End-of-Support Date in 20.04.2021, it is no longer
  supported, and firmware development has ceased. It is recommended to replace the device with a newer
  model.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/184100");
  script_xref(name:"URL", value:"https://eu.dlink.com/uk/en/products/dap-1320-wireless-range-extender");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( revcomp( a:version, b:"1.21b05" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.21b05", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
