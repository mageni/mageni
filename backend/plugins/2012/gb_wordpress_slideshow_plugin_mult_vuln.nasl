###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_slideshow_plugin_mult_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress Slideshow Plugin Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802999");
  script_version("$Revision: 13962 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-14 11:02:12 +0200 (Fr, 14 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-10-18 12:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Slideshow Plugin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-92.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Oct/97");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524452/30/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site
  and to gain sensitive information like installation path location.");

  script_tag(name:"affected", value:"WordPress Slideshow Plugin version 2.1.12");

  script_tag(name:"insight", value:"- Input passed via the 'randomId', 'slides' and 'settings'
  parameters to views/SlideshowPlugin/slideshow.php, 'settings', 'inputFields'
  parameters to views/SlideshowPluginPostType/settings.php and
  views/SlideshowPluginPostType/style-settings.php is not properly
  sanitised before being returned to the user.

  - Direct request to the multiple '.php' files reveals the full installation path.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress Slideshow Plugin and is prone
  to cross site scripting and full path disclosure vulnerabilities.");

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
url = dir + '/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPlugin/slideshow.php?randomId="><script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\);</script>")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);