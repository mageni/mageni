###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_45134.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# ISC BIND 'allow-query' Zone ACL Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100928");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-02 12:48:19 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(45134);
  script_cve_id("CVE-2010-3615");
  script_name("ISC BIND 'allow-query' Zone ACL Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45134");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2010-3615");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");
  script_tag(name:"summary", value:"ISC BIND is prone to a security-bypass vulnerability.");
  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to
  bypass zone-and-view Access Control Lists (ACLs) to perform unintended queries.");
  script_tag(name:"affected", value:"Versions prior to BIND 9.7.2-P3 are vulnerable.");

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

if( version =~ "^9\.7" ) {
  if( version_is_less( version:version, test_version:"9.7.2.P3" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"9.7.2-P3" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );