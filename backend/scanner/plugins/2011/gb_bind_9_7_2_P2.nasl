###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_9_7_2_P2.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# ISC BIND 9 < 9.7.2-P2 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103031");
  script_version("$Revision: 12014 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(45015, 45385);
  script_cve_id("CVE-2010-4172", "CVE-2010-3762");
  script_name("ISC BIND 9 < 9.7.2-P2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45385");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45015");
  script_xref(name:"URL", value:"http://ftp.isc.org/isc/bind9/9.7.2-P2/RELEASE-NOTES-BIND-9.7.2-P2.html");
  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2010-3615");
  script_xref(name:"URL", value:"https://www.redhat.com/security/data/cve/CVE-2010-3762.html");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100124923");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"ISC BIND is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"1. A remote denial-of-service vulnerability because
  the software fails to handle certain bad signatures in a DNS query.

  An attacker can exploit this issue to cause the application to crash,
  denying service to legitimate users.

  2. A security-bypass vulnerability.

  Successfully exploiting this issue allows remote attackers to bypass
  zone-and-view Access Control Lists (ACLs) to perform unintended
  queries.");
  script_tag(name:"affected", value:"Versions prior to BIND 9.7.2-P2 are vulnerable.");

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

if( version_in_range( version:version, test_version:"9.7", test_version2:"9.7.2.P1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.7.2-P2" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );