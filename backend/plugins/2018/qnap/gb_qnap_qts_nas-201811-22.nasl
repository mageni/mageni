###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_nas-201811-22.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# QNAP QTS < 4.2.6 build 20180829, 4.3.3 < build 20180810, 4.3.4 < build 20180810, 4.3.5 < build 20181110 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112444");
  script_version("$Revision: 12938 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-11-29 10:00:00 +0100 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14746", "CVE-2018-14747", "CVE-2018-14748", "CVE-2018-14749");

  script_name("QNAP QTS < 4.2.6 build 20180829, 4.3.3 < build 20180810, 4.3.4 < build 20180810, 4.3.5 < build 20181110 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to a multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Command Injection which could allow remote attackers to run arbitrary commands on the NAS. (CVE-2018-14746)

  - NULL Pointer Dereference which could allow remote attackers to crash the NAS media server. (CVE-2018-14747)

  - Improper Authorization which could allow remote attackers to power off the NAS. (CVE-2018-14748)

  - Buffer Overflow which could have unspecified impact on the NAS. (CVE-2018-14749)");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to run arbitrary commands on
  the NAS, crash the NAS media server, power off the NAS or have other unspecified impact on the NAS.");
  script_tag(name:"affected", value:"QNAP QTS 4.2.6 build 20180829 and earlier versions, 4.3.3 build 20180829 and earlier versions
  and 4.3.4 build 20181008 and earlier versions and 4.3.5 build 20181013 and earlier versions.");
  script_tag(name:"solution", value:"Update to version 4.2.6 build 20181026, 4.3.3 build 20181029,
  4.3.4 build 20181026 or 4.3.5 build 20181110 respectively.");

  script_xref(name:"URL", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201811-22");

  exit(0);
}


include( "host_details.inc" );
include( "version_func.inc" );

if( ! model = get_kb_item( "qnap/model" ) ) exit( 0 );
CPE = "cpe:/h:qnap:" + tolower( model );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "4.2.6_20181026" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.6 build 20181026" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.0_00000000", test_version2: "4.3.3_20180829" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.3 build 20181029" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.4_00000000", test_version2: "4.3.4_20181008" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4 build 20181026" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.5_00000000", test_version2: "4.3.5_20181013" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4 build 20181110" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
