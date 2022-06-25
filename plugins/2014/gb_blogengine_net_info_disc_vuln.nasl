##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blogengine_net_info_disc_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# BlogEngine.NET 'sioc.axd' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803791");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-6953");
  script_bugtraq_id(64635);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-08 13:24:03 +0530 (Wed, 08 Jan 2014)");
  script_name("BlogEngine.NET 'sioc.axd' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is running BlogEngine.NET and is prone to information disclosure
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to read
  the configuration file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to an improper access restriction to 'sioc.axd', which
  contains system configuration files.");
  script_tag(name:"affected", value:"BlogEngine.net version 2.8.0.0 and earlier");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the target system and obtain valuable information such as access
  credentials.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/553166");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

benPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/blogengine", "/blog/blogengine", cgi_dirs(port:benPort)))
{
  if(http_vuln_check(port:benPort, url:dir + "/", pattern:">BlogEngine.NET<",
                 check_header:TRUE))
  {
    if(http_vuln_check(port:benPort, url: dir + "/sioc.axd", pattern:"sioc:Usergroup>",
       check_header:TRUE,  extra_check: make_list(">BlogEngine.NET","sioc_id")))
    {
      security_message(port:benPort);
      exit(0);
    }
  }
}

exit(99);
