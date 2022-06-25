###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_37522.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Squid Header-Only Packets Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100412");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_cve_id("CVE-2010-0308");
  script_bugtraq_id(37522);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Squid Header-Only Packets Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37522");
  script_xref(name:"URL", value:"http://events.ccc.de/congress/2009/Fahrplan//attachments/1483_26c3_ipv4_fuckups.pdf");
  script_xref(name:"URL", value:"http://www.squid-cache.org/");

  script_tag(name:"summary", value:"Squid is prone to a remote denial-of-service vulnerability.");
  script_tag(name:"impact", value:"An attacker can exploit this to issue to crash the affected
  application, denying service to legitimate users.");
  script_tag(name:"solution", value:"Update to version 3.1.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.1.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
