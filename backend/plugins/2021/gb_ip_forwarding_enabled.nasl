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
  script_oid("1.3.6.1.4.1.25623.1.0.147205");
  script_version("2021-12-02T15:04:18+0000");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-11-24 07:35:11 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("IP Forwarding Enabled - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("global_settings.nasl", "smtp_settings.nasl"); # nb: The setting for get_3rdparty_domain() is currently located in this VT.
  script_mandatory_keys("keys/islocalnet");
  script_exclude_keys("keys/islocalhost");

  script_tag(name:"summary", value:"Checks if the remote host has IP forwarding enabled.");

  script_tag(name:"vuldetect", value:"Sends a crafted Local Link Layer (LLL) frame and checks the
  response.");

  exit(0);
}

include("misc_func.inc");
include("string_hex_func.inc");
include("version_func.inc");
include("dump.inc");
include("network_func.inc");
include("byte_func.inc");
include("smtp_func.inc");

# nb: Available since GOS 21.04.10 / openvas-scanner 21.04.4
if (!defined_func("get_local_mac_address_from_ip") ||
    !defined_func("send_arp_request") ||
    !defined_func("forge_frame") ||
    !defined_func("send_frame") ||
    !defined_func("dump_frame"))
  exit(0);

if (islocalhost())
  exit(0);

if (!islocalnet())
  exit(0);

debug = 0;
src_ip = this_host();
dst_ip = get_host_ip();
ext_host = get_3rdparty_domain();
ext_ips = resolve_hostname_to_multiple_ips(hostname: ext_host);

# nb: Loop over the list (e.g. if IPv4 and IPv6 IPs are returned) and pick out the first IP matching
# the used IP version.
foreach _ext_ip (ext_ips) {
  if (TARGET_IS_IPV6()) {
    if (":" >< _ext_ip) {
      ext_ip = _ext_ip;
      break;
    }
  } else {
    if (":" >!< _ext_ip) {
      ext_ip = _ext_ip;
      break;
    }
  }
}

# nb: Just a fallback if anything has gone wrong (e.g. we're scanning an IPv4 target but the
# as external defined host is only reachable via IPv6).
if (!ext_ip)
  ext_ip = resolve_host_name(hostname: ext_host);

src_mac = get_local_mac_address_from_ip(src_ip);
if (isnull(src_mac)) {
  if (debug) display("DEBUG: get_local_mac_address_from_ip() call failed for IP '", src_ip, "'");
  exit(0);
}

dst_mac = send_arp_request(host: dst_ip);
if (isnull(dst_mac)) {
  if (debug) display("DEBUG: send_arp_request() call failed for IP '", dst_ip, "'");
  exit(0);
}

if (debug) display("DEBUG:\nSource IP:       ", src_ip, "\nSource MAC:      ", src_mac, "\nDestination IP:  ", dst_ip, "\nDestination MAC: ", dst_mac, "\nExternal IP:     ", ext_ip, " (", ext_host, ")");

split = split(src_mac, sep: ":", keep:FALSE);
for (i = 0; i < max_index(split); i++)
  src_mac_raw += hex2raw(s: split[i]);

split = split(dst_mac, sep: ":", keep:FALSE);
for (i = 0; i < max_index(split); i++)
  dst_mac_raw += hex2raw(s: split[i]);

function create_packet(src_ip, ext_ip, ip_proto, src_mac_raw, debug) {

  local_var src_ip, ext_ip, ip_proto, src_mac_raw, debug;
  local_var ret_arry, vt_strings, data, src_port, dst_port, dst_ip, IPV6_VERSION, ip_packet, tcp_packet, filter, ether_proto;
  local_var ICMP6_ECHO_REQ_TYPE, ICMP6_ECHO_RES_TYPE, ICMP_ID, ICMP_ID_REVERSE, icmp_packet;
  local_var ICMP_ECHO_REQ_TYPE, ICMP_ECHO_RES_TYPE;

  ret_arry = make_array();
  vt_strings = get_vt_strings();
  data = vt_strings["default_rand"];
  src_port = (rand() + 1024) % 65535;
  dst_port = (rand() + 1024) % 65535;

  # nb: On TCP we're setting src_ip = dst_ip, on ICMP we're trying to sent an ICMP ECHO REQUEST to
  # an external system.
  if (ip_proto == IPPROTO_TCP)
    dst_ip = src_ip;
  else
    dst_ip = ext_ip;

  if (TARGET_IS_IPV6()) {

    # nb: Previous versions had calculated a wrong IPv6 flow label
    # (see https://github.com/greenbone/openvas/pull/545) which
    # requires this workaround here.
    # TODO: Remove once all GOS/GVM versions < 20.8.0 are EOL.
    if (version_is_less(version: OPENVAS_VERSION, test_version: "20.8.0"))
      IPV6_VERSION = 0x60;
    else
      IPV6_VERSION = 6;

    # TODO: Use forge_ip_v6_packet once all GOS/GVM versions < 20.8.0 are EOL.
    ip_packet = forge_ipv6_packet(ip6_v    : IPV6_VERSION,
                                  ip6_p    : ip_proto,
                                  ip6_src  : src_ip,
                                  ip6_dst  : dst_ip,
                                  # nb: Those are the defaults from (see note in function description on the reason):
                                  # https://github.com/greenbone/openvas-scanner/blob/v21.4.2/nasl/nasl_packet_forgery_v6.c#L112-L126
                                  ip6_tc   : 0,
                                  ip6_fl   : 0,
                                  ip6_hlim : 64);

    if (!ip_packet) {
      if (debug) display("DEBUG: forge_ipv6_packet() call failed.");
      return NULL;
    }

    if (debug) { display("---[ Crafted IPv6 packet ]---"); dump_ipv6_packet(ip_packet); }

    if (ip_proto == IPPROTO_TCP) {

      tcp_packet = forge_tcp_v6_packet(ip6           : ip_packet,
                                       data          : data,
                                       th_sport      : src_port,
                                       th_dport      : dst_port,
                                       # nb: Those are the defaults from (see note in function description on the reason):
                                       # https://github.com/greenbone/openvas-scanner/blob/v21.4.2/nasl/nasl_packet_forgery_v6.c#L520-L538
                                       th_seq        : rand(),
                                       th_ack        : 0,
                                       th_x2         : 0,
                                       th_off        : 5,
                                       th_flags      : 0,
                                       th_win        : 0,
                                       th_urp        : 0,
                                       update_ip_len : TRUE);

      if (!tcp_packet) {
        if (debug) display("DEBUG: forge_tcp_v6_packet() call failed.");
        return NULL;
      }

      ret_arry["packet"] = tcp_packet;

      if (debug) { display("---[ Crafted TCP packet ]---"); dump_tcp_v6_packet(tcp_packet); }

      filter = string("ether dst ", hexstr(src_mac_raw), " and dst port ", dst_port);
      ret_arry["filter"] = filter;

    } else {

      ICMP6_ECHO_REQ_TYPE = 128;
      ICMP6_ECHO_RES_TYPE = 129;
      ICMP_ID = rand() % 65536;

      # nb: See description on the filter below
      set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
      ICMP_ID_REVERSE = mkdword(ICMP_ID);
      # nb: Reset to the default of byte_func.inc
      set_byte_order(BYTE_ORDER_BIG_ENDIAN);
      ICMP_ID_REVERSE = getword(blob: ICMP_ID_REVERSE);

      icmp_packet = forge_icmp_v6_packet(ip6       : ip_packet,
                                         icmp_type : ICMP6_ECHO_REQ_TYPE,
                                         icmp_code : 0,
                                         icmp_seq  : 1,
                                         icmp_id   : ICMP_ID,
                                         data      : data);

      if (!icmp_packet) {
        if (debug) display("DEBUG: forge_icmp_v6_packet() call failed.");
        return NULL;
      }

      ret_arry["packet"] = icmp_packet;

      if (debug) { display("---[ Crafted ICMPv6 packet ]---"); dump_icmp_v6_packet(icmp_packet); }

      # nb: Some older pcap versions seems do not support the following syntax:
      # filter = string("ether dst ", hexstr(src_mac_raw), " and icmp6[0] = ", ICMP6_ECHO_RES_TYPE, " and icmp6[4:2] = ", ICMP_ID);
      # and are throwing a "pcap_compile : IPv6 upper-layer protocol is not supported by proto[x]" message so we're parsing the type and id directly
      # from the IPv6 payload to work around this.
      # Note that icmp6[4:2] seems to be able to handle Big vs. Little Endian where ip6[44:2] isn't so we're using "ICMP_ID_REVERSE" and "ICMP_ID" here "just to be safe".
      filter = string("ether dst ", hexstr(src_mac_raw), " and ip6[40] = ", ICMP6_ECHO_RES_TYPE, " and ( ip6[44:2] = ", ICMP_ID, " or ip6[44:2] = ", ICMP_ID_REVERSE, " )");
      ret_arry["filter"] = filter;

    }

    ether_proto = get_ethertype_proto_value(proto: "ipv6");
    ret_arry["ether_proto"] = ether_proto;
    return ret_arry;
  } else {

    ip_packet = forge_ip_packet(ip_v   : 4,
                                ip_hl  : 5,
                                ip_tos : 0,
                                ip_len : 20,
                                ip_id  : rand() % 65535,
                                ip_p   : ip_proto,
                                ip_ttl : 255,
                                ip_off : 0,
                                ip_src : src_ip,
                                ip_dst : dst_ip);

    if (!ip_packet) {
      if (debug) display("DEBUG: forge_ip_packet() call failed.");
      return NULL;
    }

    if (debug) { display("---[ Crafted IPv4 packet ]---"); dump_ip_packet(ip_packet); }

    if (ip_proto == IPPROTO_TCP) {

      tcp_packet = forge_tcp_packet(ip       : ip_packet,
                                    th_ack   : 0,
                                    th_dport : dst_port,
                                    th_flags : TH_SYN,
                                    th_sport : src_port,
                                    th_x2    : 0,
                                    th_off   : 5,
                                    th_win   : 1024,
                                    th_urp   : 0,
                                    data     : data);

      if (!tcp_packet) {
        if (debug) display("DEBUG: forge_tcp_packet() call failed.");
        return NULL;
      }

      ret_arry["packet"] = tcp_packet;

      if (debug) { display("---[ Crafted TCP packet ]---"); dump_tcp_packet(tcp_packet); }

      filter = string("ether dst ", hexstr(src_mac_raw), " and dst port ", dst_port);
      ret_arry["filter"] = filter;

    } else {

      ICMP_ECHO_REQ_TYPE = 8;
      ICMP_ECHO_RES_TYPE = 0;
      ICMP_ID = rand() % 65536;

      icmp_packet = forge_icmp_packet(icmp_type : ICMP_ECHO_REQ_TYPE,
                                      icmp_code : 0,
                                      icmp_seq  : 1,
                                      icmp_id   : ICMP_ID,
                                      data      : data,
                                      ip        : ip_packet);

      if (!icmp_packet) {
        if (debug) display("DEBUG: forge_icmp_packet() call failed.");
        return NULL;
      }

      ret_arry["packet"] = icmp_packet;

      if (debug) { display("---[ Crafted ICMP packet ]---"); dump_icmp_packet(icmp_packet); }

      filter = string("ether dst ", hexstr(src_mac_raw), " and icmp[0] = ", ICMP_ECHO_RES_TYPE, " and icmp[4:2] = ", ICMP_ID);
      ret_arry["filter"] = filter;

    }

    ether_proto = get_ethertype_proto_value(proto: "ipv4");
    ret_arry["ether_proto"] = ether_proto;
    return ret_arry;
  }
}

if (TARGET_IS_IPV6()) {
  # nb: This variable was added in GOS/GVM 20.8.0, see:
  # https://github.com/greenbone/openvas/pull/549
  # TODO: Remove once all GOS/GVM versions < 20.8.0 are EOL.
  if (!IPPROTO_ICMPV6)
    IPPROTO_ICMPV6 = 58;
  ip_protos = make_list(make_list(IPPROTO_TCP, IPPROTO_ICMPV6));
} else {
  ip_protos = make_list(make_list(IPPROTO_TCP, IPPROTO_ICMP));
}

foreach ip_proto (ip_protos) {

  packet_info = create_packet(src_ip: src_ip, ext_ip: ext_ip, ip_proto: ip_proto, src_mac_raw: src_mac_raw, debug: debug);
  if (!packet_info)
    continue;

  payload = packet_info["packet"];
  ether_proto = packet_info["ether_proto"];

  frame = forge_frame(src_haddr: src_mac_raw, dst_haddr: dst_mac_raw, ether_proto: ether_proto, payload: payload);
  if (!frame) {
    if (debug) display("DEBUG: forge_frame() call failed.");
    continue;
  }

  if (debug) { display("---[ Crafted Ethernet Frame ]---"); dump_frame(frame: frame); }

  filter = packet_info["filter"];

  if (debug) display("---[ Used PCAP filter ]---", "\n", filter);

  recv = send_frame(frame: frame, pcap_filter: filter, timeout: 10);

  if (!recv) {
    if (debug) display("DEBUG: No answer received with send_frame().");
    continue;
  } else {
    if (debug) { display("---[ Received Ethernet Frame ]---"); dump_frame(frame: recv); }
  }

  if (recv) {
    if (ip_proto == IPPROTO_TCP)
      report_proto = "a TCP";
    else
      report_proto = "an ICMP";
    report = "It was possible to route " + report_proto + " packet through the target host and received an answer which means IP forwarding is enabled.";
    log_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
