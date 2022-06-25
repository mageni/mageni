# OpenVAS Vulnerability Test
# Description: Tripwire for Webpages Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications by rd :
#	- we read www/banner/<port> first
#	- egrep()
#	- no output of the version (redundant with the server banner)
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10743");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Tripwire for Webpages Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/apache");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5RP0L1540K.html");

  script_tag(name:"summary", value:"We detected the remote web server as running
  Tripwire for web pages under the Apache web server.");

  script_tag(name:"impact", value:"This software allows attackers to gather sensitive information
  about your server configuration.");

  script_tag(name:"solution", value:"Modify the banner used by Apache by adding the option
  'ServerTokens' to 'ProductOnly' in httpd.conf.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)
  exit(0);

if(egrep(string:banner, pattern:"^Server: Apache.* Intrusion/")) {
  security_message(port:port);
  exit(0);
}

exit(99);