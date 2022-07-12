###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advanced_image_hosting_xss_vuln.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# Advanced Image Hosting Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802155");
  script_version("$Revision: 12010 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(49457);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Advanced Image Hosting Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69609");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104799/aihimgid-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
script code in the browser of an unsuspecting user in the context of the
affected site.");
  script_tag(name:"affected", value:"Advanced Image Hosting version 2.3");
  script_tag(name:"insight", value:"The flaw is due to failure in the 'report.php' script to
properly sanitize user supplied input in 'img_id' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Advanced Image Hosting and is prone to
cross site scripting vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir( make_list_unique( "/aihspro", "/aih", "/", cgi_dirs( port:port ) ) )
{

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("Powered by:" >< res && '>AIH' >< res)
  {
    req = http_get(item:string(dir, '/report.php?img_id="><script>alert' +
            '(document.cookie)</script>'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && '"><script>alert(document.cookie)</script>' >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}
