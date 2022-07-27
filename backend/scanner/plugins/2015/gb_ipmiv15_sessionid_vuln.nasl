###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipmiv15_sessionid_vuln.nasl 11291 2018-09-07 14:48:41Z mmartin $
#
# Dell iDRAC Weak SessionID Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105939");
  script_version("$Revision: 11291 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 16:48:41 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-21 09:55:57 +0700 (Wed, 21 Jan 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-8272");
  script_bugtraq_id(71750);

  script_name("Dell iDRAC Weak SessionID Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");

  script_dependencies("gb_ipmi_detect.nasl", "gb_ipmi_default_pw.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/credentials");

  script_tag(name:"summary", value:"IPMI v1.5 SessionID's are not randomized sufficiently across
different channels.");

  script_tag(name:"vuldetect", value:"Checks randomness of the session ID's by activating sessions.");

  script_tag(name:"insight", value:"Dell iDRAC6 and iDRAC7 does not properly randomize session ID values,
which makes it easier for remote attackers to execute arbitrary commands via a brute-force attack.");

  script_tag(name:"impact", value:"A remote attacker might be able to execute arbitrary commands via a
brute-force attack.");

  script_tag(name:"affected", value:"Dell iDRAC6 modular before 3.65, iDRAC6 monolithic before 1.98 and
iDRAC7 before 1.57.57.");

  script_tag(name:"solution", value:"Updates from Dell are available which will disable IPMI v1.5. As
a workaround disable IPMI v1.5.");

  script_xref(name:"URL", value:"https://labs.mwrinfosecurity.com/blog/2015/01/08/cve-2014-8272/");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("http_func.inc");

function checksum(data) {
  checksum = 0;
  for (i=0; i<strlen(data); i++) {
     checksum = (checksum + ord(data[i])) % 256;
  }
  return 0x100 - checksum;
}

function createHash(alg, password, sessionid, data, seqnr) {
  if (alg == "MD5") {
    return MD5(password + sessionid + data + seqnr + password);
  } else {
    return password;
  }
}

port = 623;
if (!get_udp_port_state(port))
  exit(0);

creds = get_kb_item("ipmi/credentials");
if (!creds)
  exit(0);

creds = split(creds, sep:"/", keep:0);
username = creds[0];
password = creds[1];
if (!username || !password)
  exit(0);

soc = open_sock_udp(port);
if(!soc) {
  exit(0);
}

getChannelAuthCap = raw_string(0x06, 0x00, 0xff, 0x07,        # RMCP
                               0x00,                          # Auth Type = NONE
                               0x00, 0x00, 0x00, 0x00,        # Session Seq Number
                               0x00, 0x00, 0x00, 0x00,        # Session ID
                               0x09,                          # Message Length
                               # IPMI Message
                               0x20,                          # Responder Address
                               0x18,                          # netFn/rsLUN
                               checksum(data:raw_string(0x20, 0x18)),
                               0x81,                          # Requester Address
                               0x04,                          # reqSeq, reqLUN
                               0x38,                          # Get Channel Auth Capabilities (command)
                               0x0e,                          # Channel Number (this channel)
                               0x04,                          # Request Administrator level
                               checksum(data:raw_string(0x81, 0x04, 0x38, 0x0e, 0x04))
                              );
send(socket:soc, data:getChannelAuthCap);
recv = recv(socket:soc, length:1024);
if (!recv)
  exit(0);

auth_support = dec2bin(dec:ord(recv[22]));

if (auth_support[5] == 1) {
  authAlg = "MD5";
  authType = raw_string(0x02);
}
else if (auth_support[3] == 1) {
  authAlg = "PW";
  authType = raw_string(0x04);
}
else {
  exit(0);	# No suitable authentication algorithm so just exit
}

for (j=0; j<10; j++) {
  paddedUsername = username;
  while (strlen(paddedUsername) < 16) {
    paddedUsername = paddedUsername + raw_string(0x00);
  }

  getSessChallenge = raw_string(0x06, 0x00, 0xff, 0x07,     # RMCP
                                0x00,                       # Auth Type = NONE
                                0x00, 0x00, 0x00, 0x00,     # Session Seq Number
                                0x00, 0x00, 0x00, 0x00,     # Session ID
                                0x18,                       # Message Length
                                # IPMI Message
                                0x20,                       # Responder Address
                                0x18,                       # netFn/rsLUN
                                0xc8,                       # checksum
                                0x81,                       # Requester Address
                                0x08,                       # reqSeq, reqLUN
                                0x39,                       # Get Session Challenge (command)
                                authType,                   # Auth Type for Challenge
                                paddedUsername,
                                checksum(data:raw_string(0x81, 0x08, 0x39, authType, paddedUsername))
                               );

  send(socket:soc, data:getSessChallenge);
  recv = recv(socket:soc, length:1024);

  # Error Checking
  if (!recv || hexstr(recv[20]) != "00") {
    break;
  }

  tmp_sessionID = substr(recv, 21, 24);
  challenge = substr(recv, 25, 40);
  sequenceNum = raw_string(0x00, 0x00, 0x00, 0x00);
  # Activate Session
  paddedPassword = password;
  while (strlen(paddedPassword) < 16) {
    paddedPassword = paddedPassword + raw_string(0x00);
  }

  chksum = checksum(data:raw_string(0x81, 0x0c, 0x3a, authType, 0x04, challenge, 0xaa, 0x9b, 0x59, 0x3a));
  data = raw_string(0x20, 0x18, 0xc8, 0x81, 0x0c, 0x3a, authType, 0x04, challenge,
                    0xaa, 0x9b, 0x59, 0x3a, chksum);
  authCode = createHash(alg: authAlg, password: paddedPassword, sessionid: tmp_sessionID,
                        data: data, seqnr: sequenceNum);

  activateSession = raw_string(0x06, 0x00, 0xff, 0x07,      # RMCP
                               authType,                    # Auth Type
                               0x00, 0x00, 0x00, 0x00,      # Session Seq Number
                               tmp_sessionID,
                               authCode,                    # AuthCode
                               0x1d,                        # Message Length
                               # IPMI Message
                               0x20,                        # Responder Address
                               0x18,                        # netFn/rsLUN
                               0xc8,                        # checksum
                               0x81,                        # Requester Address
                               0x0c,                        # reqSeq/reqLUN
                               0x3a,                        # Activate Session (command)
                               authType,                    # Auth Type
                               0x04,                        # Max Priv Level (Administrator level)
                               challenge,
                               0xaa, 0x9b, 0x59, 0x3a,      # initial outbound seq number
                               chksum
                              );

  send(socket:soc, data:activateSession);
  recv = recv(socket:soc, length:1024);

  # Error checking
  if (!recv) {
    continue;
  }
  if (strlen(recv) > 41 && hexstr(recv[36]) == "00") {
    sessionid = substr(recv, 38, 41);
    sessionids[j] = raw_string(hexstr(sessionid[3]), hexstr(sessionid[2]), hexstr(sessionid[1]),
                               hexstr(sessionid[0]));
  }
  else {
    continue;
  }

  sequenceNum = raw_string(0x01, 0x00, 0x00, 0x00);
  chksum = checksum(data:raw_string(0x81, 0x10, 0x3c, sessionid));
  data = raw_string(0x20, 0x18, 0xc8, 0x81, 0x10, 0x3c, sessionid, chksum);
  authCode = createHash(alg: authAlg, password: paddedPassword, sessionid: sessionid,
                        data: data, seqnr: sequenceNum);

  # Close the session (some devices have very limited session slots available)
  closeSession = raw_string(0x06, 0x00, 0xff, 0x07,     # RMCP
                            authType,                   # Auth Type
                            0x01, 0x00, 0x00, 0x00,     # Session Seq Number
                            sessionid,                  # Session ID
                            authCode,                   # AuthCode
                            0x0b,                       # Message Length
                            # IPMI Message
                            0x20,                       # Responder Address
                            0x18,                       # netFn/rsLUN
                            0xc8,                       # checksum
                            0x81,                       # Requester Address
                            0x10,                       # reqSeq, reqLUN
                            0x3c,                       # Close Session (command)
                            sessionid,                  # SessionID
                            chksum
                           );
  send(socket:soc, data:closeSession);
  recv = recv(socket:soc, length:1024);
}

close(soc);

const_diff = 0;
for (i=1; i<10; i++) {
  id1 = hex2dec(xvalue:sessionids[i-1]);
  id2 = hex2dec(xvalue:sessionids[i]);
  if (id1 < id2) {
    const_diff = id2 - id1;
    break;
  }
}

if (const_diff > 0) {
  vulnerable = TRUE;
  notmatched = 0;

  for (i=1; i<10; i++) {
    if (hex2dec(xvalue:sessionids[i]) - hex2dec(xvalue:sessionids[i-1]) != const_diff) {
      if (notmatched < 2)
        notmatched++;
      else
        vulnerable = FALSE;
    }
  }
}

if (vulnerable) {
  security_message(port:port);
}

exit(0);
