###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_auth_bypass_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Vbulletin Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:vbulletin:vbulletin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804144");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6129");
  script_bugtraq_id(62909);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-15 12:55:00 +0530 (Fri, 15 Nov 2013)");
  script_name("Vbulletin Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass security
  restrictions.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to bypass authentication.");
  script_tag(name:"insight", value:"The flaw is due to the 'upgrade.php' script which does not require
  authentication, which allows to create administrative accounts via
  the customerid, htmldata[password], htmldata[confirmpassword], and
  htmldata[email] parameters.");
  script_tag(name:"solution", value:"Upgrade to version 4.2.2 or 5.0.5 or later.");
  script_tag(name:"summary", value:"This host is running vBulletin and is prone to security bypass vulnerability.");
  script_tag(name:"affected", value:"vBulletin version 4.1.x and 5.x.x are affected.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123811");
  script_xref(name:"URL", value:"http://www.net-security.org/secworld.php?id=15743");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.vbulletin.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

foreach dir2( make_list("", "/core" ) ) {

  url = dir + dir2  + '/install/upgrade.php';

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res && res =~ "HTTP/1.. 200 OK" &&
      "vBulletin" >< res && "Customer Number<" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );