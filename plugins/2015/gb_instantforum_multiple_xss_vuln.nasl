###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_instantforum_multiple_xss_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# InstantASP InstantForum.NET Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805291");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2014-9468");
  script_bugtraq_id(72660);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-02-26 11:32:25 +0530 (Thu, 26 Feb 2015)");
  script_name("InstantASP InstantForum.NET Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with InstantASP
  InstantForum.NET and is prone to multiple cross-site scripting
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper
  validation of input passed via 'SessionID' parameter to Join.aspx and
  Logon.aspx scripts before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"InstantASP InstantForum.NET versions 4.1.3,
  4.1.2, 4.1.1, 4.0.0, 4.1.0 and 3.4.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/instantforum", "/InstantForum", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir, "/"), port:http_port);

  if(rcvRes && rcvRes =~ "Powered by.*>InstantForum")
  {
    url = dir + "/Logon.aspx?SessionId=><script>alert(document.cookie)</script>";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\)</script>",
       extra_check:make_list(">InstantForum", ">Login<")))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
