###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_42982.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Squid Proxy String Processing NULL Pointer Dereference Denial Of Service Vulnerability
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100789");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_bugtraq_id(42982);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3072");
  script_name("Squid Proxy String Processing NULL Pointer Dereference Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42982");
  script_xref(name:"URL", value:"http://www.squid-cache.org/");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2010_3.txt");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Squid is prone to a remote denial-of-service vulnerability caused by a
  NULL pointer dereference.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to crash,
  denying service to legitimate users. Due to the nature of the issue, code execution may be possible, however,
  it has not been confirmed.");

  script_tag(name:"affected", value:"Squid 3.0 to 3.0.STABLE25 Squid 3.1 to 3.1.7 Squid 3.2 to 3.2.0.1 are affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.1", test_version2:"3.1.7" ) ||
    version_in_range( version:vers, test_version:"3.2", test_version2:"3.2.0.1" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE26/3.1.8/3.2.0.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );