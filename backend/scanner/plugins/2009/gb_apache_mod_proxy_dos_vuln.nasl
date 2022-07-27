###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_proxy_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Apache 'mod_proxy_http.c' Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800827");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1890");
  script_bugtraq_id(35565);
  script_name("Apache 'mod_proxy_http.c' Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35691");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1773");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=790587&r2=790586&pathrev=790587");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause Denial of Service
  to the legitimate user by CPU consumption.");

  script_tag(name:"affected", value:"Apache HTTP Server version prior to 2.3.3.");

  script_tag(name:"insight", value:"The flaw is due to error in 'stream_reqbody_cl' function in 'mod_proxy_http.c'
  in the mod_proxy module. When a reverse proxy is configured, it does not properly
  handle an amount of streamed data that exceeds the Content-Length value via crafted requests.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server and is prone to Denial of Service
  vulnerability.");

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

if( version_is_less( version:vers, test_version:"2.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );