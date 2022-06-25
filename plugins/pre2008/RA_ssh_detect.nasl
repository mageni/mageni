# OpenVAS Vulnerability Test
# $Id: RA_ssh_detect.nasl 13576 2019-02-11 12:44:20Z cfischer $
# Description: RemotelyAnywhere SSH detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Broken link deleted
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.10921");
  script_version("$Revision: 13576 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 13:44:20 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RemotelyAnywhere SSH detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Malware");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/remotelyanywhere/detected");

  script_tag(name:"summary", value:"The RemotelyAnywhere SSH server is running on this system.");

  script_tag(name:"insight", value:"According to NAVCIRT attackers love this management tool.

  If you installed it, ignore this warning. If not, your machine is
  compromised by an attacker.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default:22);
banner = get_ssh_server_banner(port:port);
if (! banner)
  exit(0);

if (ereg(pattern:'SSH-[0-9.-]+[ \t]+RemotelyAnywhere', string:banner))
{
  log_message(port:port);
}