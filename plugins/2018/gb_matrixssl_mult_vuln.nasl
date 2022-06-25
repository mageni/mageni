###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_matrixssl_mult_vuln.nasl 8849 2018-02-16 14:02:28Z asteins $
#
# MatrixSSL 3.7.2 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113090");
  script_version("$Revision: 8849 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-16 15:02:28 +0100 (Fri, 16 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 12:37:48 +0100 (Wed, 24 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1000415", "CVE-2017-1000417");

  script_name("MatrixSSL 3.7.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"Multiple vulnerabilities exist in MatrixSSL.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MatrixSSL has an incorrect UTCTime date range validation in its X.509 certificate validation process resulting in some certificates have their expiration (beginning) year extended (delayed) by 100 years.

  MatrixSSL adopts a collision-prone OID comparison logic resulting in possible spoofing of OIDs (e.g. in ExtKeyUsage extension) on X.509 certificates.");
  script_tag(name:"affected", value:"MatrixSSL version 3.7.2 and below.");
  script_tag(name:"solution", value:"Update to MatrixSSL 3.8.2 or above.");

  script_xref(name:"URL", value:"https://www.ieee-security.org/TC/SP2017/papers/231.pdf");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/blob/master/doc/CHANGES.md");

  exit( 0 );
}

CPE = "cpe:/a:peersec_networks:matrixssl";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.7.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.2" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
