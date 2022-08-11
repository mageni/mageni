###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icinga2_mult_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Icinga2 < 2.8.2 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113121");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-02 11:56:30 +0100 (Fri, 02 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-6532", "CVE-2018-6533", "CVE-2018-6534", "CVE-2018-6535", "CVE-2018-6536", "CVE-2017-16933");

  script_name("Icinga2 < 2.8.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icinga2_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga2 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Effects of successful exploitation range from password disclosure over Denial
  of Service to an attacker gaining complete control over the target system.");
  script_tag(name:"affected", value:"Icinga2 through version 2.8.1");
  script_tag(name:"solution", value:"Update to version 2.8.2 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/5715");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/5850");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/issues/5991");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/6103");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/6104");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/issues/5793");
  script_xref(name:"URL", value:"https://www.icinga.com/2018/03/22/icinga-2-8-2-released/");

  exit(0);
}

CPE = "cpe:/a:icinga:icinga2";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( !version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.8.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
