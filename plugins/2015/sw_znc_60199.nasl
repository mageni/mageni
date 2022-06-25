###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_znc_60199.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# ZNC WebAdmin Multiple NULL Pointer Dereference Denial of Service Vulnerabilities
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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

CPE = 'cpe:/a:znc:znc';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111032");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-29 12:00:00 +0200 (Sat, 29 Aug 2015)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2013-2130");
  script_bugtraq_id(60199);
  script_name("ZNC WebAdmin Multiple NULL Pointer Dereference Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("znc_detect.nasl");
  script_mandatory_keys("znc/version");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/60199");
  script_xref(name:"URL", value:"http://en.znc.in/wiki/ZNC");

  script_tag(name:"summary", value:"ZNC is prone to multiple remote denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit these issues to crash the application, resulting
  in denial-of-service conditions.");

  script_tag(name:"affected", value:"These issues affect ZNC 1.0.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"1.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
