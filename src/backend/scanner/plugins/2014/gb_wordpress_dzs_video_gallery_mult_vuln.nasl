###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dzs_video_gallery_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# WordPress Digital Zoom Studio (DZS) Video Gallery Plugin Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804899");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-9094");
  script_bugtraq_id(68525);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-11-28 20:20:50 +0530 (Fri, 28 Nov 2014)");
  script_name("WordPress Digital Zoom Studio (DZS) Video Gallery Plugin Multiple Vulnerabilities");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"summary", value:"This host is installed with WordPress
  Digital Zoom Studio (DZS) Video Gallery Plugin and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Input passed via 'designrand'and 'swfloc'  parameters to
  dzs-videogallery/deploy/designer/preview.php script is not properly validated
  before returning it to users.

  - Direct request for the /videogallery.php and /admin/sliderexport.php scripts
  discloses the software's installation path.

  - Input passed via the 'src' parameter is not properly sanitized upon submission
  to the img.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within the
  trust relationship between their browser and the server, result in loss of
  confidentiality and execute arbitrary commands.");

  script_tag(name:"affected", value:"WordPress Digital Zoom Studio (DZS) Video
  Gallery Plugin");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126846/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/65");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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

url = dir + "/wp-content/plugins/dzs-videogallery/deploy/designer/"
          + 'preview.php?swfloc="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document\.cookie\)</script>",
  extra_check:">Video"))
{
  security_message(port:http_port);
  exit(0);
}
