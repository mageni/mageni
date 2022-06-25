# OpenVAS Vulnerability Test
# $Id: ncacn_http.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Detect CIS ports
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.10761");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect CIS ports");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ncacn_http");

  script_xref(name:"URL", value:"http://support.microsoft.com/support/kb/articles/Q282/2/61.ASP");
  script_xref(name:"URL", value:"http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp");

  script_tag(name:"solution", value:"Disable CIS with DCOMCNFG or protect CIS ports by a Firewall.");

  script_tag(name:"summary", value:"This detects the CIS ports by connecting to the server and
  processing the buffer received.

  CIS (COM+ Internet Services) are RPC over HTTP tunneling and requires IIS to operate.
  CIS ports shouldn't be visible on internet but only behind a firewall.

  If you do not use this service, then disable it as it may become
  a security threat in the future, if a vulnerability is discovered.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item("Services/ncacn_http");
if(!port)
  exit(0);

banner = get_kb_item("ncacn_http/banner/" + port);
if(banner) {
  data = string("There is a CIS (COM+ Internet Services) on this port\nServer banner :\n", banner);
  log_message(port:port, data:data);
}

exit(0);
