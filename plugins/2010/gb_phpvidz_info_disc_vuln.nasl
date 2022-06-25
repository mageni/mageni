##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpvidz_info_disc_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# PHPvidz Administrative Credentials Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801549");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHPvidz Administrative Credentials Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/May/129");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15606/");
  script_xref(name:"URL", value:"http://www.mail-archive.com/bugtraq@securityfocus.com/msg33846.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"insight", value:"phpvidz uses a system of flat files to maintain application
state. The administrative password is stored within the '.inc' file and
is included during runtime.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running PHPvidz and is prone to administrative
credentials disclosure vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
obtain sensitive information.");
  script_tag(name:"affected", value:"PHPvidz version 0.9.5");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

pcmsPort = get_http_port(default:80);

foreach dir( make_list_unique( "/phpvidz_0.9.5", "/phpvidz", cgi_dirs( port:pcmsPort ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:pcmsPort);

  if(">PHPvidz<" >< rcvRes)
  {
    if(http_vuln_check(port:pcmsPort, url:dir + "/includes/init.inc",
                       pattern:"(define .'ADMINPASSWORD)"))
    {
      security_message(port:pcmsPort);
      exit(0);
    }
  }
}
