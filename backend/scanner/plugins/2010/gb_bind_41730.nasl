###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_41730.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# ISC BIND 9 'RRSIG' Record Type Remote Denial of Service Vulnerability
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100717");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-16 12:38:11 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(41730);
  script_cve_id("CVE-2010-0213");
  script_name("ISC BIND 9 'RRSIG' Record Type Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41730");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2010-0213");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"ISC BIND is prone to a remote denial-of-service vulnerability because
  the software fails to handle certain record types.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to fall
  into an infinite loop, denying service to legitimate users.");
  script_tag(name:"affected", value:"BIND versions 9.7.1 and 9.7.1-P1 are vulnerable.");

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

if( version_is_equal( version:version, test_version:"9.7.1" ) ||
    version_is_equal( version:version, test_version:"9.7.1.P1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references." );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );