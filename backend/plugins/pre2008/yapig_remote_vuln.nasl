# OpenVAS Vulnerability Test
# $Id: yapig_remote_vuln.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: YaPiG Remote Server-Side Script Execution Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14269");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10891);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_name("YaPiG Remote Server-Side Script Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to YaPiG 0.92.2 or later.");

  script_tag(name:"summary", value:"The remote version of YaPiG may allow a remote attacker to execute
  malicious scripts on a vulnerable system.");

  script_tag(name:"insight", value:"This issue exists due to a lack of sanitization of user-supplied data.
  It is reported that an attacker may be able to upload content that will be saved on the server with a '.php'
  extension.  When this file is requested by the attacker, the contents of the file will be parsed and executed by the
  PHP engine, rather than being sent.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to execute malicious
  script code on a vulnerable server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0756.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/yapig", "/gallery", "/photos", "/photo", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache(item:string(dir, "/"), port:port);
  if(!res)
    continue;

  #Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
  if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string:res)) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );