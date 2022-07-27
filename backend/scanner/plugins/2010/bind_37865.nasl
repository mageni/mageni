###############################################################################
# OpenVAS Vulnerability Test
# $Id: bind_37865.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# ISC BIND 9 DNSSEC Bogus NXDOMAIN Response Remote Cache Poisoning Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated By : Antu Sanadi <santu@secpod.com> 2010-01-129 #6962
# Added the  CVE-2010-0290 and CVE-2010-0382
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
  script_oid("1.3.6.1.4.1.25623.1.0.100458");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(37865);
  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_name("ISC BIND 9 DNSSEC Bogus NXDOMAIN Response Remote Cache Poisoning Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37865");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/360341");
  script_xref(name:"URL", value:"https://www.isc.org/advisories/CVE-2010-0097");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"ISC BIND 9 is prone to a remote cache-poisoning vulnerability.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to manipulate cache data,
  potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
  service attacks.");
  script_tag(name:"affected", value:"Versions prior to the following are vulnerable:

  BIND 9.4.3-P5 BIND 9.5.2-P2 BIND 9.6.1-P3");

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

version = str_replace(find:"-", string: version, replace:".");

if( version =~ "9\.[0-4]+" ) {
  if( version_is_less( version:version, test_version: "9.4.3.P5" ) ) {
    fix = "9.4.3-P5";
    VULN = TRUE;
  }
}

else if( version =~ "9\.5" ) {
  if( version_is_less( version:version, test_version:"9.5.2.P2" ) ) {
    fix = "9.5.3-P2";
    VULN = TRUE;
  }
}

else if( version =~ "9\.6" ) {
  if( version_is_less( version:version, test_version:"9.6.1.P3" ) ) {
    fix = "9.6.1-P3";
    VULN = TRUE;
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );