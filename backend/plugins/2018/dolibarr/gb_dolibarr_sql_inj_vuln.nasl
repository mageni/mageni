###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_sql_inj_vuln.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr < 7.0.2 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113196");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-05-24 14:25:13 +0200 (Thu, 24 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-9019", "CVE-2018-10092", "CVE-2018-10094", "CVE-2018-10095");

  script_name("Dolibarr < 7.0.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dolibarr is prone to multiple vulnerabilities:

  - SQL Injection (CVE-2018-9019)

  - Arbitrary command execution (CVE-2018-10092)

  - SQL Injection (CVE-2018-10094)

  - Cross-site scripting vulnerability (CVE-2018-10095)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code on
the target host.");

  script_tag(name:"affected", value:"Dolibarr through version 7.0.1.");

  script_tag(name:"solution", value:"Update to version 7.0.2.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/commit/83b762b681c6dfdceb809d26ce95f3667b614739");
  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/blob/7.0.2/ChangeLog");

  exit(0);
}

CPE = "cpe:/a:dolibarr:dolibarr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "7.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
