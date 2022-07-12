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
  script_oid("1.3.6.1.4.1.25623.1.0.146440");
  script_version("2021-08-05T07:12:10+0000");
  script_tag(name:"last_modification", value:"2021-09-08 10:53:11 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-08-05 04:43:00 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:N");

  script_cve_id("CVE-1999-0524");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ICMP Netmask Reply Information Disclosure");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("os_fingerprint.nasl", "global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6", "ICMPv4/AddressMaskRequest/failed");

  script_tag(name:"summary", value:"The remote host responded to an ICMP netmask request.");

  script_tag(name:"insight", value:"The Netmask Reply is an ICMP message which replies to a Netmask
  message.");

  script_tag(name:"impact", value:"This information might give an attacker information for further
  reconnaissance and/or attacks (e.g. subnet structure, filter bypass, etc.).");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc950.html");
  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc6918.html");

  exit(0);
}

if (TARGET_IS_IPV6())
  exit(0);

if (islocalhost())
  exit(0);

if (get_kb_item("ICMPv4/AddressMaskRequest/failed"))
  exit(0);

own_ip = this_host();
target_ip = get_host_ip();

icmp_addrmask_request = 17;
icmp_addrmask_reply = 18;
icmp_id = rand() % 65536;

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_off: 0, ip_id: 9, ip_tos: 0, ip_p: IPPROTO_ICMP,
                     ip_len: 20, ip_src: own_ip, ip_ttl: 255);
icmp = forge_icmp_packet(ip: ip, icmp_type: icmp_addrmask_request, icmp_code: 0, icmp_seq: 1, icmp_id: icmp_id,
                         data: crap(length: 4, data: raw_string(0)));

filter = string("icmp and src host ", target_ip, " and dst host ", own_ip, " and icmp[0:1] = ",
                icmp_addrmask_reply);

for (i = 0; i < 5; i++) {
  recv = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 3);

  if (recv) {
    type = get_icmp_element(icmp: recv, element: "icmp_type");
    if (type == icmp_addrmask_reply) {
      data = get_icmp_element(icmp: recv, element: "data");
      if (strlen(data) != 4)
        exit(0);

      netmask = ord(data[0]) + "." + ord(data[1]) + "." + ord(data[2]) + "." + ord(data[3]);

      report = "Received Netmask: " + netmask;
      log_message(port: 0, data: report, proto: "icmp");
      exit(0);
    }
  }
}

exit(0);
