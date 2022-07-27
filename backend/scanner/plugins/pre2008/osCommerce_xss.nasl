# OpenVAS Vulnerability Test
# $Id: osCommerce_xss.nasl 13238 2019-01-23 11:14:26Z cfischer $
# Description: osCommerce Cross Site Scripting Bugs
#
# Authors:
# K-Otik.com <ReYn0@k-otik.com>
# Ref added by rd
#
# Copyright:
# Copyright (C) 2003 k-otik.com
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
#

#  Message-ID: <009e01c2eef9$069683b0$0900a8c0@compcaw8>
#  From: Daniel Alcántara de la Hoz <seguridad@iproyectos.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: [IPS] osCommerce multiple XSS vulnerabilities

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11437");
  script_version("$Revision: 13238 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7151, 7153, 7155, 7156, 7158);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("osCommerce Cross Site Scripting Bugs");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2003 k-otik.com");
  script_dependencies("oscommerce_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Software/osCommerce");

  script_xref(name:"URL", value:"http://secunia.com/advisories/8368/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/11590");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1006342");

  script_tag(name:"solution", value:"Upgrade to a newer version.");

  script_tag(name:"summary", value:"osCommerce is prone to a cross site scripting attack.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = string(dir, "/default.php?error_message=<script>window.alert(document.cookie);</script>");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if(!buf) exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
   "<script>window.alert(document.cookie);</script>" >< buf)
{
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);