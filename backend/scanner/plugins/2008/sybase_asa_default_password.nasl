###############################################################################
# OpenVAS Vulnerability Test
#
# Sybase ASA default database password
#
# Authors:
# David Lodge
# This script is based on sybase_blank_password.nasl which is (C) Tenable Security
#
# Copyright:
# Copyright (C) 2008 David Lodge
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

CPE = 'cpe:/a:sybase:adaptive_server_enterprise';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80088");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sybase ASA default database password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2008 David Lodge");
  script_family("Databases");
  script_require_ports("Services/sybase", 5000);
  script_dependencies("gb_sybase_tcp_listen_detect.nasl");
  script_mandatory_keys("sybase/tcp_listener/detected");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"summary", value:"The remote Sybase SQL Anywhere / Adaptive Server Anywhere server uses
  default credentials ('DBA' / 'SQL').

  It was possible to connect to the remote database service using default credentials.");

  script_tag(name:"impact", value:"An attacker may use this flaw to execute commands against the remote host,
  as well as read the database content.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

login_pkt_hdr = raw_string(
   0x02,        # Login packet type
   0x00,        # Not last packet
   0x02, 0x00,  # Size of packet
   0x00, 0x00,  # Channel
   0x00,        # Packet Number
   0x00         # Window
);

login_pkt_hdr2 = raw_string(
   0x02,        # Login packet type;
   0x01,        # Not last packet
   0x00, 0x61,  # Size of packet
   0x00, 0x00,  # Channel
   0x00,        # Packet Number
   0x00         # Window
);

nul=raw_string(0x00);

# data for hostname including length
pkt_src_hostname = crap(data:nul, length:31);
# username is here
# password is here
pkt_src_process = raw_string("1",crap(data:nul, length:29), 0x01);
pkt_magic1 = raw_string(
   0x03, 0x01, 0x06, 0x0a, 0x09, 0x01
);
pkt_bulk_copy = raw_string(0x00);
pkt_magic2 = crap(data:nul, length:9);
pkt_client = raw_string("OpenVA", crap(data:nul, length:24), 0x06);
# database is here
pkt_magic3 = raw_string(0x00);
# password repeats here but with length first!
pkt_magic4 = crap(data:nul, length:223);
pkt_passwordlength_plus2 = raw_string (0x05);
pkt_version = raw_string(0x05, 0x00, 0x00, 0x00);
pkt_library = raw_string("CT-Library", 0x0a);
pkt_library_version = raw_string(0x05, 0x00, 0x00, 0x00);
pkt_magic6 = raw_string(0x00, 0x0d, 0x11);
pkt_language = raw_string("us_english", crap(data:nul, length:14));
pkt_language2 = raw_string(crap(data:nul, length:6),0x0a);
pkt_magic7 = raw_string(0x00);
pkt_old_secure = raw_string(0x00, 0x00);
pkt_encrypted = raw_string(0x00);
pkt_magic8 = raw_string(0x00);
pkt_sec_spare = crap(data:nul, length:9);
pkt_char_set = raw_string("UTF-8", crap(data:nul, length:25), 0x05);
pkt_magic9 = raw_string(0x01);
pkt_block_size = raw_string("512",0x00,0x00,0x00,0x03);
pkt_magic10 = raw_string(
   0x00, 0x00, 0x00, 0x00, 0xe2, 0x16, 0x00, 0x01, 0x09, 0x00,
   0x00, 0x06, 0x6d, 0x7f, 0xff, 0xff, 0xff, 0xfe, 0x02, 0x09,
   0x00, 0x00, 0x00, 0x00, 0x0a, 0x68, 0x00, 0x00, 0x00
);

function make_sql_login_pkt(database, username, password)
{
    local_var dblen, dbuf, dlen, dpad, pblen, pbuf, plen, ppad, sql_packet, ublen, ubuf, ulen, upad;

    dlen = strlen(database);
    ulen = strlen(username);
    plen = strlen(password);

    dpad = 30 - dlen;
    upad = 30 - ulen;
    ppad = 30 - plen;

    dbuf = "";
    ubuf = "";
    pbuf = "";

    nul = raw_string(0x00);

    if(ulen)
    {
        ublen = raw_string(ulen % 255);
    } else {
        ublen = raw_string(0x00);
    }

    if(plen)
    {
        pblen = raw_string(plen % 255);
    } else {
        pblen = raw_string(0x00);
    }

    if(dlen)
    {
        dblen = raw_string(dlen % 255);
    } else {
        dblen = raw_string(0x00);
    }

    dbuf = string(database, crap(data:nul, length:dpad));
    ubuf = string(username, crap(data:nul, length:upad));
    pbuf = string(password, crap(data:nul, length:ppad));

    sql_packet = string(
       login_pkt_hdr, pkt_src_hostname, ubuf, ublen, pbuf, pblen,
       pkt_src_process, pkt_magic1, pkt_bulk_copy, pkt_magic2,
       pkt_client, dbuf, dblen, pkt_magic3, pblen, pbuf, pkt_magic4,
       pkt_passwordlength_plus2, pkt_version, pkt_library,
       pkt_library_version, pkt_magic6, pkt_language, login_pkt_hdr2,
       pkt_language2,
       pkt_magic7, pkt_old_secure, pkt_encrypted, pkt_magic8,
       pkt_sec_spare, pkt_char_set, pkt_magic9, pkt_block_size,
       pkt_magic10
    );

    # returning this as a string is NOT working!
    return sql_packet;
}

if(!port = get_app_port( cpe:CPE, service:"sybase_tcp_listener" ))
  exit( 0 );

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

# this creates a variable called sql_packet
sql_packet = make_sql_login_pkt(database:"", username:"DBA", password:"SQL");
send(socket:soc, data:sql_packet);
r = recv(socket:soc, length:512);
close(soc);

# See <http://www.freetds.org/tds.html> for info on the TDS protocol
if(
   # packet seems big enough and...
   strlen(r) > 3 &&
   # response from server and...
   ord(r[0x00]) == 4 &&
   # packet length agrees with what's in the packet header
   (ord(r[2])*256 + ord(r[3])) == strlen(r)
  ) {
  # Find the server response to the login request.
  i = 8;
  while (i < strlen(r)) {
    type = ord(r[i]);
    if (type == 0xFD || type == 0xFE || type == 0xFF) {
      exit(0);
    }
    if (type == 0xAD) {
      ack = ord(r[i+3]);
      ver = ord(r[i+4]);
      if ( (ver == 5 && ack == 5) || (ver == 4 && ack == 1) ) {
        security_message(port:port);
        exit(0);
      }
    }
    len = ord(r[i+1]) + ord(r[i+2])*256;
    i += 3 + len;
  }
}