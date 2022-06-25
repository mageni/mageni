###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_knot_dns_dos_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Knot DNS 1.5.2 Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113152");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-10 15:35:37 +0200 (Tue, 10 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-0486");
  script_bugtraq_id(70097);

  script_name("Knot DNS 1.5.2 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_knot_dns_version_detect.nasl");
  script_mandatory_keys("KnotDNS/installed");

  script_tag(name:"summary", value:"Knot DNS is vulnerable to a denial of service.
  By sending a specially-crafted DNS message, a remote attacker could exploit this vulnerability to cause the application to crash.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Knot DNS through version 1.5.2.");
  script_tag(name:"solution", value:"Update to version 1.5.3");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/96185");
  script_xref(name:"URL", value:"https://www.knot-dns.cz/download/");

  exit(0);
}

CPE = "cpe:/a:knot:dns";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
