# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170541");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-14 20:06:16 +0000 (Mon, 14 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-34241");

  script_name("CUPS 2.2.0 < 2.4.6 Use After Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to an use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CUPS logs data of free memory to the logging service AFTER the
  connection has been closed, when it should have logged the data right before. This is a use after
  free bug that impacts the entire cupsd process. The exact cause of this issue is the function
  `httpClose(con->http)` being called in `scheduler/client.c`. The problem is that httpClose always,
  provided its argument is not null, frees the pointer at the end of the call, only for cupsdLogClient
  to pass the pointer to httpGetHostname. This issue happens in function `cupsdAcceptClient` if
  LogLevel is warn or higher and in two scenarios: there is a double-lookup for the IP Address
  (HostNameLookups Double is set in `cupsd.conf`) which fails to resolve, or if CUPS is compiled with
  TCP wrappers and the connection is refused by rules from `/etc/hosts.allow` and `/etc/hosts.deny`.");

  script_tag(name:"affected", value:"CUPS version 2.2.0 prior to 2.4.6.");

  script_tag(name:"solution", value:"Update to version 2.4.6 or later.");

  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/security/advisories/GHSA-qjgh-5hcq-5f25");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/releases/tag/v2.4.6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if ( version_in_range_exclusive( version:version, test_version_lo:"2.2.0", test_version_up:"2.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.4.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
