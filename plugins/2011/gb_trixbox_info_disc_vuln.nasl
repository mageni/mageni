###############################################################################
# OpenVAS Vulnerability Test
#
# Trixbox Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802210");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_bugtraq_id(48503);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Trixbox Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102627/trixboxfop-enumerate.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3052);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to obtain valid
  usernames, which may aid them in brute-force password cracking or other attacks.");

  script_tag(name:"affected", value:"Trixbox version 2.8.0.4 and prior.");

  script_tag(name:"insight", value:"The flaw is due to Trixbox returning valid usernames via a http
  GET request to a Flash Operator Panel(FOP) file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Trixbox and is prone to information disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

res = http_get_cache(item:"/user/index.php",  port:port);

if("<TITLE>trixbox - User Mode</TITLE>" >< res)
{
  url = "/panel/variables.txt";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
    ("Content-Type: text/plain" >< res) && ("Asterisk" >< res)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}
