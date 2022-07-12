###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_znc_42314.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# ZNC Multiple Denial Of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:znc:znc';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100758");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-13 12:44:16 +0200 (Fri, 13 Aug 2010)");
  script_bugtraq_id(42314);
  script_cve_id("CVE-2010-2812", "CVE-2010-2934");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ZNC Multiple Denial Of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("znc_detect.nasl");
  script_mandatory_keys("znc/version");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42314");
  script_xref(name:"URL", value:"http://en.znc.in/wiki/ZNC");
  script_xref(name:"URL", value:"http://znc.svn.sourceforge.net/viewvc/znc?view=revision&revision=2093");
  script_xref(name:"URL", value:"http://znc.svn.sourceforge.net/viewvc/znc?view=revision&revision=2095");

  script_tag(name:"summary", value:"ZNC is prone to a multiple remote denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit these issues to crash the application,
  resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"ZNC 0.092 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"0.092" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.094" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );