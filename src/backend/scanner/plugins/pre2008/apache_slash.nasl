# OpenVAS Vulnerability Test
# $Id: apache_slash.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Check for Apache Multiple / vulnerability
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# changes by rd : - script description
#                 - more verbose report
#                 - check for k < 16 in find_index()
#                 - script id
#
# Copyright:
# Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10440");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1284);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0505");
  script_name("Check for Apache Multiple / vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_tag(name:"solution", value:"Upgrade to the most recent version of Apache.");

  script_tag(name:"summary", value:"Certain versions of Apache for Win32 have a bug wherein remote users
  can list directory entries.");

  script_tag(name:"insight", value:"Specifically, by appending multiple /'s
  to the HTTP GET command, the remote Apache server will list all files
  and subdirectories within the web root (as defined in httpd.conf).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function find_index(k, port) {

  if(k < 16)
    k = 17;

  for(q = k - 16; q < k; q++) {
    buf = http_get(item:crap(length:q, data:"/"), port:port);
    incoming = http_keepalive_send_recv(port:port, data:buf);
    if (!incoming)
      continue;

    if ("Index of /" >< incoming)  {
      report = string(q, " slashes will cause the directory contents to be listed.");
      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if( ! banner || "Apache" >!< banner || "Win32" >!< banner )
  exit(0);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res || "Index of /" >< res)
  exit(0);

for(i=2; i < 512; i=i+16) {
  buf = http_get(item:crap(length:i, data:"/"), port:port);
  incoming = http_keepalive_send_recv(port:port, data:buf);
  if(!incoming)
    continue;

  if("Forbidden" >< incoming) {
    find_index(k:i, port:port);
  }
}

exit(99);