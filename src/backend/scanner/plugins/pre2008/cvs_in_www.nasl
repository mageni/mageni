###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvs_in_www.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# CVS/Entries
#
# Authors:
# Nate Haggard (SecurityMetrics inc.)
# changes by rd: pattern matching to determine if the file is CVS indeed
#
# Copyright:
# Copyright (C) 2002 Nate Haggard (SecurityMetrics inc.)
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10922");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CVS/Entries");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Nate Haggard (SecurityMetrics inc.)");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Your website allows read access to the CVS/Entries file.");

  script_tag(name:"impact", value:"This exposes all file names in your CVS module on your website.");

  script_tag(name:"solution", value:"Change your website permissions to deny access to your CVS directory.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host))exit(0);

res = is_cgi_installed_ka(item:"/CVS/Entries", port:port);
# is_cgi_installed_ka takes care of servers that always return 200
# This was tested with nessus 1.2.1
if(!res) exit(0);

soc = http_open_socket(port);
file = string("/CVS/Entries");
req = http_get(item:file, port:port);
send(socket:soc, data:req);
h = http_recv_headers2(socket:soc);
r = http_recv_body(socket:soc, headers:h, length:0);
http_close_socket(soc);

warning = string("/CVS/Entries contains the following: \n", r);
security_message(port:port, data:warning);
exit(0);
