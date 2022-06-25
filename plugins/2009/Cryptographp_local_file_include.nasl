###############################################################################
# OpenVAS Vulnerability Test
# $Id: Cryptographp_local_file_include.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Cryptographp 'index.php' Local File Include Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100060");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-17 15:36:47 +0100 (Tue, 17 Mar 2009)");
  script_bugtraq_id(34122);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Cryptographp 'index.php' Local File Include Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cryptographp is prone to a local file-include vulnerability because
  it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view files and execute
  local scripts from the Cryptographp directory in the context of the webserver process. This may aid in
  further attacks.");

  script_tag(name:"affected", value:"Cryptographp 1.4 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34122");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach d (make_list("/crypt"))
{
  req = string("GET ", d, "/cryptographp.inc.php?cfg=verifier.php&sn=PHPSESSID& HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept-Language: en-us,en,de;\r\n",
               "Cookie: cryptcookietest=1\r\n",
               "Connection: close\r\n\r\n");
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!buf)
    continue;

  if ( egrep(pattern:".*Cannot redeclare.*", string: buf) ) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);