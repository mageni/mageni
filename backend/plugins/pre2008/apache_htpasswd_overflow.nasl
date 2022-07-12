# OpenVAS Vulnerability Test
# $Id: apache_htpasswd_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Apache <= 1.3.33 htpasswd local overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Fixed by Tenable 26-May-2005:
#   - added BIDs 13777 and 13778
#   - extended banner check to cover 1.3.33 as well.
#   - edited description.
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
  script_oid("1.3.6.1.4.1.25623.1.0.14771");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(13777, 13778);
  script_name("Apache <= 1.3.33 htpasswd local overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Privilege escalation");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/apache");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0345.html");

  script_tag(name:"solution", value:"Make sure htpasswd does not run setuid and is not accessible
  through any CGI scripts.");

  script_tag(name:"summary", value:"The remote host appears to be running Apache 1.3.33 or older.

  There is a local buffer overflow in the 'htpasswd' command in these
  versions that may allow a local user to gain elevated privileges if
  'htpasswd' is run setuid or a remote user to run arbitrary commands
  remotely if the script is accessible through a CGI.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Apache" >!< banner)
  exit(0);

serv = strstr(banner, "Server:");
if(!serv)
  exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-9]|3[0-3])))", string:serv)) {
  security_message(port:port);
  exit(0);
}

exit(99);