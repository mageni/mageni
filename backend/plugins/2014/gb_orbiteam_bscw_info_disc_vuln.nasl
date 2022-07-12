###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orbiteam_bscw_info_disc_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# OrbiTeam BSCW 'op' Parameter Information Disclosure Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804297");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-2301");
  script_bugtraq_id(67284);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-16 11:22:00 +0530 (Fri, 16 May 2014)");
  script_name("OrbiTeam BSCW 'op' Parameter Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with OrbiTeam BSCW and is prone to information
  disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to read
  the filename of a document.");
  script_tag(name:"insight", value:"The flaw exists as the program associates filenames of documents with values
  mapped from the 'op' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information by enumerating the names of all objects stored in BSCW without prior authentication.");
  script_tag(name:"affected", value:"OrbiTeam BSCW before version 5.0.8");
  script_tag(name:"solution", value:"Upgrade to OrbiTeam BSCW version 5.0.8 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/May/37");
  script_xref(name:"URL", value:"https://xforce.iss.net/xforce/xfdb/93030");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126551");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-003");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.bscw.de/english/product.html");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

bscwPort = get_http_port(default:80);

rcvRes = http_get_cache(item:"/", port:bscwPort);

if(">BSCW administrator<" >!< rcvRes){
  exit(0);
}

req = http_get(item:"/pub/bscw.cgi/?op=inf", port:bscwPort);
rcvRes = http_keepalive_send_recv(port:bscwPort, data:req, bodyonly:TRUE);
if('"banner ruled_banner"' >< rcvRes)
{
  ##Grab the relocated link
  rcvRes = eregmatch(pattern:'The document can be found <A HREF="' +
           'http://.*(/pub/bscw.cgi/(.*)/?op=inf)">here', string:rcvRes);
  if(rcvRes[1]){
    url = rcvRes[1];
  }

  req = http_get(item:url, port:bscwPort);
  rcvRes = http_keepalive_send_recv(port:bscwPort, data:req, bodyonly:TRUE);
  if("server_logo_bscw.jpg" >< rcvRes)
  {
    rcvRes = eregmatch(pattern:'The document can be found <A HREF="' +
             'http://.*(/pub/bscw.cgi/(.*)/?op=inf)">here', string:rcvRes);
    if(rcvRes[1]){
      url = rcvRes[1];
    }

    req = http_get(item:url, port:bscwPort);
    rcvRes = http_send_recv(port:bscwPort, data:req, bodyonly:TRUE);

    if(rcvRes && rcvRes =~ '<td.*class="iValueB".*width=.*">(.*)</td>')
    {
      security_message(port:bscwPort);
      exit(0);
    }
  }
}

exit(99);
