###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpbb_mypage_plugin_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# phpBB MyPage Plugin 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902641");
  script_version("$Revision: 11997 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:30:52 +0530 (Tue, 13 Dec 2011)");
  script_name("phpBB MyPage Plugin 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"http://www.phpbbexploit.com/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18212/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107586/mypage-sql.txt");
  script_xref(name:"URL", value:"http://www.crackhackforum.com/thread-188498-post-344690.html#pid344690");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"phpBB Mypage plugin version 0.2.3 and prior");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input sent via the 'id' parameter to 'mypage.php', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running phpBB MyPage plugin and is prone to SQL
  injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url =  dir + "/mypage.php?id=1'";

if( http_vuln_check( port:port, url:url, pattern:"You have an error in your SQL syntax;", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );