###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_multiple_vuln_01_11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ISC BIND 9 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103030");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_bugtraq_id(45133, 45137);
  script_cve_id("CVE-2010-3613", "CVE-2010-3614");
  script_name("ISC BIND 9 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45133");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45137");
  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2010-3613");
  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2010-3614");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100124923");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"ISC BIND is prone to multiple Vulnerabilities.");
  script_tag(name:"insight", value:"1. A remote denial-of-service vulnerability.
  An attacker can exploit this issue to cause the affected service to
  crash, denying service to legitimate users.

  2. A security vulnerability that affects the integrity security property
  of the application.");
  script_tag(name:"affected", value:"BIND versions 9.6.2 to 9.6.2-P2, 9.6-ESV to 9.6-ESV-R2 and 9.7.0 to
  9.7.2-P2 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

version = str_replace( find:"-", string:version, replace:"." );

if( version_in_range( version:version, test_version:"9.6.2", test_version2:"9.6.2.P1" ) ||
    version_in_range( version:version, test_version:"9.6.ESV", test_version2:"9.6.ESV.R1" ) ||
    version_in_range( version:version, test_version:"9.7", test_version2:"9.7.2.P2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references." );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );