# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170542");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-14 20:06:16 +0000 (Mon, 14 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-32324");

  script_name("CUPS < 2.4.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("Denial of Service");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability in the function format_log_line
  could allow remote attackers to cause a denial-of-service(DoS) on the affected system. Exploitation
  of the vulnerability can be triggered when the configuration file cupsd.conf sets the value of
  loglevel to DEBUG.");

  script_tag(name:"affected", value:"CUPS prior to version 2.4.3.");

  script_tag(name:"solution", value:"Update to version 2.4.3 or later.");

  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/security/advisories/GHSA-cxc6-w2g7-69p7");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/releases/tag/v2.4.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if ( version_is_less( version:version, test_version:"2.4.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.4.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
