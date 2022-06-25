###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dnsmasq_54353.nasl 10932 2018-08-13 02:58:36Z ckuersteiner $
#
# Dnsmasq Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103509");
  script_bugtraq_id(54353);
  script_cve_id("CVE-2012-3411");
  script_version("$Revision: 10932 $");
  script_name("Dnsmasq Remote Denial of Service Vulnerability");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-13 04:58:36 +0200 (Mon, 13 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 11:18:48 +0200 (Wed, 11 Jul 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("dnsmasq_version.nasl");
  script_mandatory_keys("dnsmasq/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54353");
  script_xref(name:"URL", value:"http://www.thekelleys.org.uk/dnsmasq/doc.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=833033");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause denial-of-service
  conditions through a stream of spoofed DNS queries producing large results.");
  script_tag(name:"affected", value:"Dnsmasq versions 2.62 and prior are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"Dnsmasq is prone to a denial-of-service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"2.63" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.63" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
