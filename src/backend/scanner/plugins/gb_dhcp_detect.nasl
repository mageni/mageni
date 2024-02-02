# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151309");
  script_version("2023-11-30T05:06:26+0000");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-28 07:36:14 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dynamic Host Configuration Protocol (DHCP) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Service detection");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(67);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"UDP based detection via DHCPINFORM message of services
  supporting the Dynamic Host Configuration Protocol (DHCP).");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc2131");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("pcap_func.inc");
include("port_service_func.inc");
include("string_hex_func.inc");
include("version_func.inc");

# Currently only on IPv4
if (TARGET_IS_IPV6())
  exit(0);

srv_port = 67;
client_port = 68;

if (!get_udp_port_state(srv_port))
  exit(0);

ownip = this_host();
targetip = get_host_ip();

buf = split(ownip, sep: ".", keep: FALSE);
raw_ownip = raw_string(mkbyte(buf[0]), mkbyte(buf[1]), mkbyte(buf[2]), mkbyte(buf[3]));

trans_id = mkdword(rand_int_range(min: 1000, max: 10000));
hex_trans_id = hexstr(trans_id);

src_mac = get_local_mac_address_from_ip(ownip);
if (isnull(src_mac))
  exit(0);

split = split(src_mac, sep: ":", keep: FALSE);
for (i = 0; i < max_index(split); i++)
  src_mac_raw += hex2raw(s: split[i]);

dhcpinform = raw_string(0x01,                                # Message Type: Boot Request
                        0x01,                                # Hardware Type: Ethernet
                        0x06,                                # Hardware Address Length
                        0x00,                                # Hops
                        trans_id,                            # Transaction ID
                        0x00, 0x00,                          # Seconds elapsed
                        0x00, 0x00,                          # Boot flags: Unicast
                        raw_ownip,                           # Client IP Address
                        0x00, 0x00, 0x00, 0x00,              # Your (client) IP Address
                        0x00, 0x00, 0x00, 0x00,              # Next server IP Address
                        0x00, 0x00, 0x00, 0x00,              # Relay Agent Address
                        src_mac_raw,                         # Client MAC Address
                        mkpad(10),                           # Client hardware address padding
                        mkpad(64),                           # Server host name not given
                        mkpad(128),                          # Boot file name not given
                        0x63, 0x82, 0x53, 0x63,              # Magic cookie: DHCP
                        0x35, 0x01, 0x08,                    # DHCP Message Type (Inform)
                        0x37, 0x40, 0xfc, 0x01, 0x02, 0x03,  # Parameter Request List (more or less request all possible parameters from the server)
                        0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
                        0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                        0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                        0x3a, 0x3b, 0x3c, 0x3d, 0x43, 0x42,
                        0x33, 0x04, 0x00, 0x00, 0x00, 0x01,  # IP Address Lease Time
                        0xff);                               # End

filter = "src host " + targetip + " and dst host " + ownip + " and udp and src port " + srv_port +
         " and dst port " + client_port;

recv = pcap_tcp_udp_send_recv(port: srv_port, srcport: client_port, data: dhcpinform, proto: "udp",
                              pcap_filter: filter);

# nb: Check for the right start and the DHCP magic cookie in the response
if (isnull(recv) || hexstr(recv) !~ "^020106.*63825363")
  exit(0);

set_kb_item(name: "dhcp/server/detected", value: TRUE);

service_register(port: srv_port, proto: "dhcp_server", ipproto: "udp");

if (strlen(recv) > 240) {
  option_blob = substr(recv, 240);
  i = 0;

  while (i <= strlen(option_blob)) {
    option = ord(option_blob[i]);
    if (option == 255) # End
      break;

    len = ord(option_blob[i + 1]);
    data = substr(option_blob, i + 2, i + 2 + len);

    if (option == 1) {  # Subnet Mask
      subnet = ord(data[0]) + "." + ord(data[1]) + "." + ord(data[2]) + "." + ord(data[3]);
      extra += "Subnet Mask:            " + subnet + '\n';
    }

    if (option == 3) {  # Router
      router = ord(data[0]) + "." + ord(data[1]) + "." + ord(data[2]) + "." + ord(data[3]);
      extra += "Router:                 " + router + '\n';
    }

    if (option == 6) {  # Domain Name Server
      dns = ord(data[0]) + "." + ord(data[1]) + "." + ord(data[2]) + "." + ord(data[3]);
      extra += "Domain Name Server:     " + dns + '\n';
    }

    if (option == 15) { # Domain Name
      domain_name = substr(data, 0, len - 1);
      extra += "Domain Name:            " + domain_name + '\n';
    }

    if (option == 54) { # DHCP Server Identifier
      server_ident = ord(data[0]) + "." + ord(data[1]) + "." + ord(data[2]) + "." + ord(data[3]);
      extra += "DHCP Server Identifier: " + server_ident + '\n';
    }

    i += len + 2;
  }
}

report = "A DHCP server is running at this port.";

if (extra) {
  report += '\n\nThe following information was obtained:\n\n' + extra;
}

log_message(port: srv_port, proto: "udp", data: chomp(report));

exit(0);
