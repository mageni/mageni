###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_htcp_packets_dos_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Squid HTCP Packets Processing Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800473");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0639");
  script_bugtraq_id(38212);
  script_name("Squid HTCP Packets Processing Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0371");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2010_2.txt");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023587.html");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.7/changesets/12600.patch");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v3/3.0/changesets/3.0-ADV-2010_2.patch");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an affected
  server, creating a denial of service condition.");
  script_tag(name:"affected", value:"Squid Version 2.x, and 3.0 to 3.0.STABLE23");
  script_tag(name:"insight", value:"The flaw is due to error in 'htcpHandleTstRequest()' function in 'htcp.c', when
  processing malformed HTCP (Hypertext Caching Protocol) packets.");
  script_tag(name:"summary", value:"This host is running Squid and is prone to Denial of Service
  vulnerability.");
  script_tag(name:"solution", value:"Apply the patches from the references or upgrade to the squid version 3.0.STABLE24.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^2\.*" || version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE23" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE24" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );