# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147232");
  script_version("2021-11-30T08:05:58+0000");
  script_tag(name:"last_modification", value:"2021-11-30 10:53:46 +0000 (Tue, 30 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-29 05:23:58 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("DNS Recursion Enabled (UDP) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("dns_server.nasl");
  script_mandatory_keys("dns/server/udp/detected");
  script_require_udp_ports("Services/udp/domain", 53);

  script_tag(name:"summary", value:"The DNS server has recursion enabled.");

  script_tag(name:"vuldetect", value:"Sends a crafted DNS query via UDP and checks the response.");

  script_tag(name:"insight", value:"Recursion refers to the process of having the DNS server itself
  to make queries to other DNS servers on behalf of the client who made the original request.");

  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Domain_Name_System#Recursive_and_caching_name_server");

  exit(0);
}

include("byte_func.inc");
include("port_service_func.inc");
include("smtp_func.inc");

port = service_get_port(default: 53, ipproto: "udp", proto: "domain");

soc = open_sock_udp(port);
if (!soc)
  exit(0);

dom = get_3rdparty_domain();

domain = split(dom, sep: ".", keep: FALSE);

payload = "";

i = 0;
foreach part (domain) {
  payload += raw_string(strlen(domain[i])) + domain[i];
  i++;
}

# Normal request to put/get it in the cache of the target DNS server
id = rand() % 65535;
req = raw_string(mkword(id),                   # Transaction ID
                 0x01, 0x00,                   # Flags (recursion desired)
                 0x00, 0x01,                   # Questions
                 0x00, 0x00,                   # Answer RRs
                 0x00, 0x00,                   # Authority RRs
                 0x00, 0x00,                   # Additional RRs
                 payload,                      # Query
                 0x00,
                 0x00, 0x01,                   # Type (Host Address)
                 0x00, 0x01);                  # Class (IN)

send(socket: soc, data: req);
recv = recv(socket: soc, length: 1024);
close(soc);

if (isnull(recv) || strlen(recv) < 8)
  exit(0);

flags = getword(blob: recv, pos: 2);

if (flags & 0x80) {
  report = "The DNS server replied to a DNS query to '" + dom + "' with the recursion flag set in the response.";
  log_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(0);
