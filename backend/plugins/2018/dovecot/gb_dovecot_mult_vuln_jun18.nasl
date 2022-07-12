###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_mult_vuln_jun18.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Dovecot <= 2.2.34 and 2.3.0 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113213");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-26 12:28:52 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15130", "CVE-2017-15132");

  script_name("Dovecot <= 2.2.34 and 2.3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - An attacker able to generate random SNI server names could exploit TLS SNI configuration lookups,
    leading to excessive memory usage and the process to restart.

  - An abort of SASL authentication results in a memory leak in dovecot's auth client used by login processes.
    The leak has impact in high performance configuration where same login processes are reused
    and can cause the process to crash due to memory exhaustion.");
  script_tag(name:"affected", value:"Dovecot version 2.0.0 through 2.2.33 and version 2.3.0.");
  script_tag(name:"solution", value:"Update to version 2.2.34 or 2.3.1 respectively.");

  script_xref(name:"URL", value:"https://www.dovecot.org/list/dovecot-news/2018-February/000370.html");
  script_xref(name:"URL", value:"https://github.com/dovecot/core/commit/1a29ed2f96da1be22fa5a4d96c7583aa81b8b060.patch");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_is_equal( version: version, test_version: "2.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.1" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.2.33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.34" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
