###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_mult_bof_vuln.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Advantech WebAccess Multiple Buffer Overflow Vulnerabilities Jan16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
CPE = "cpe:/a:advantech:advantech_webaccess";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807041");
  script_version("2019-04-06T12:52:40+0000");
  script_cve_id("CVE-2014-9202", "CVE-2014-9208");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-06 12:52:40 +0000 (Sat, 06 Apr 2019)");
  script_tag(name:"creation_date", value:"2016-01-25 12:23:44 +0530 (Mon, 25 Jan 2016)");
  script_name("Advantech WebAccess Multiple Buffer Overflow Vulnerabilities Jan16");

  script_tag(name:"summary", value:"This host is running Advantech WebAccess
  and is prone to multiple stack-based buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper bounds
  checking when passing strings to functions in the affected DLL");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  attacker to crash the application or run arbitrary code by getting a user to
  execute the specially crafted file.");

  script_tag(name:"affected", value:"Advantech WebAccess versions
  before 8.0_20150816");

  script_tag(name:"solution", value:"Upgrade to Advantech WebAccess version
  8.0_20150816 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-258-04");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-251-01A");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_advantech_webaccess_consolidation.nasl");
  script_mandatory_keys("advantech/webaccess/detected");
  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version: vers, test_version: "8.0.2015.08.16" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "8.0.2015.08.16", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}
exit( 99 );
