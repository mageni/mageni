###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_alternate_profiles_remote_sql_inj_vuln.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# e107 alternate_profiles plugin newuser.php SQL Injection Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:e107:e107";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800303");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4785");
  script_bugtraq_id(31940);
  script_name("e107 alternate_profiles plugin newuser.php SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6849");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to compromise the application,
  access or modify data in the underlying database.");

  script_tag(name:"affected", value:"e107 version 0.7.13, alternate_profiles plugin on all running platform.");

  script_tag(name:"insight", value:"The flaw exists in newuser.php file, which does not validate user input data
  in the alternate_profiles via the id parameter.");

  script_tag(name:"solution", value:"Upgrade to e107 version 0.7.22 or later.");

  script_tag(name:"summary", value:"This host is running e107 and is prone to remote SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); #TODO: This test is broken and just checking if a file exists

  script_xref(name:"URL", value:"http://e107.org/edownload.php");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/e107_plugins/alternate_profiles/newuser.php";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "newuser" >< rcvRes && "200 OK" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit(99);