###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_49356.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# Squid Proxy Gopher Remote Buffer Overflow Vulnerability
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103233");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-30 14:29:55 +0200 (Tue, 30 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3205");
  script_bugtraq_id(49356);
  script_name("Squid Proxy Gopher Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49356");
  script_xref(name:"URL", value:"http://www.squid-cache.org/");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2011_3.txt");

  script_tag(name:"summary", value:"Squid Proxy is prone remote buffer-overflow vulnerability affects the
  Gopher-to-HTML functionality.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with the
  privileges of the vulnerable application. Failed exploit attempts will
  result in a denial-of-service condition.");
  script_tag(name:"solution", value:"The vendor released an update. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.2.0", test_version2:"3.2.0.10" ) ||
    version_is_less( version:vers, test_version:"3.1.15" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.15/3.2.0.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
