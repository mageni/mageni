###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_sql_inj_vuln_oct18_win.nasl 12858 2018-12-21 08:05:36Z ckuersteiner $
#
# PostgreSQL < 10.6, 11.x < 11.1 SQL Injection Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112428");
  script_version("$Revision: 12858 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 09:05:36 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 15:00:11 +0100 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16850");

  script_name("PostgreSQL < 10.6, 11.x < 11.1 SQL Injection Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an SQL injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A SQL Injection flaw has been discovered in PostgreSQL server in the way
  triggers that enable transition relations are dumped. The transition relation name is not correctly quoted
  and it may allow an attacker with CREATE privilege on some non-temporary schema or TRIGGER privilege on some
  table to create a malicious trigger that, when dumped and restored, would result in additional SQL statements being executed.");
  script_tag(name:"affected", value:"PostgreSQL before versions 10.6 and 11.1.");
  script_tag(name:"solution", value:"Update to version 10.6 or 11.1 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16850");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1905/");

  exit(0);
}

CPE = "cpe:/a:postgresql:postgresql";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "10.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "11.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
