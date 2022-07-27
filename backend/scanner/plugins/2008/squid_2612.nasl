###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_2612.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# Squid < 2.6.STABLE12 Denial-of-Service Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80017");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(80017);
  script_cve_id("CVE-2007-1560");
  script_name("Squid < 2.6.STABLE12 Denial-of-Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2008 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2007_1.txt");

  script_tag(name:"solution", value:"Upgrade to squid 2.6 or newer.");

  script_tag(name:"summary", value:"A vulnerability in TRACE request processing has been reported in Squid.");

  script_tag(name:"impact", value:"This flaw can be exploited by an attacker to cause a denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( egrep( pattern:"2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );