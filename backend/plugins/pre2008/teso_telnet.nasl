# OpenVAS Vulnerability Test
# $Id: teso_telnet.nasl 13634 2019-02-13 12:06:16Z cfischer $
# Description: TESO in.telnetd buffer overflow
#
# Authors:
# Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
#
# Copyright:
# Copyright (C) 2001 Pavel Kankovsky
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

# The kudos for an idea of counting of AYT replies should go
# to Sebastian <scut@nb.in-berlin.de> and Noam Rathaus
# <noamr@beyondsecurity.com>.
#
# rd: tested against Solaris 2.8, RH Lx 6.2, FreeBSD 4.3 (patched & unpatched)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10709");
  script_version("$Revision: 13634 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:06:16 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3064);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-0554");
  script_name("TESO in.telnetd buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2001 Pavel Kankovsky");
  script_family("Gain a shell remotely");
  # Must run AFTER ms_telnet_overflow-004.nasl
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_xref(name:"URL", value:"http://www.team-teso.net/advisories/teso-advisory-011.tar.gz");

  script_tag(name:"solution", value:"Comment out the 'telnet' line in /etc/inetd.conf.");

  script_tag(name:"summary", value:"The Telnet server does not return an expected number of replies
  when it receives a long sequence of 'Are You There' commands. This probably means it overflows one
  of its internal buffers and crashes.");

  script_tag(name:"impact", value:"It is likely an attacker could abuse this bug to gain
  control over the remote host's superuser.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

iac_ayt = raw_string(0xff, 0xf6);
iac_ao  = raw_string(0xff, 0xf5);
iac_will_naol = raw_string(0xff, 0xfb, 0x08);
iac_will_encr = raw_string(0xff, 0xfb, 0x26);

#
# This helper function counts AYT responses in the input stream.
# The input is read until 1. the expected number of responses is found,
# or 2. EOF or read timeout occurs.
#
# At this moment, any occurrence of "Yes" or "yes" is supposed to be such
# a response. Of course, this is wrong: some FreeBSD was observed to react
# with "load: 0.12  cmd: .log 20264 [running] 0.00u 0.00s 0% 620k"
# when the telnet negotiation have been completed. Unfortunately, adding
# another pattern to this code would be too painful (hence the negotiation
# tricks in attack()).
#
# In order to avoid an infinite loop (when testing a host that generates
# lots of junk, intentionally or unintentionally), I stop when I have read
# more than 100 * max bytes.
#
# Please note builtin functions like ereg() or egrep() cannot be used
# here (easily) because they choke on '\0' and many telnet servers send
# this character
#
# Local variables: num, state, bytes, a, i, newstate
#

function count_ayt(sock, max) {
  num = 0; state = 0;
  bytes = 100 * max;
  while (bytes >= 0) {
    a = recv(socket:sock, length:1024);
    if (!a) return (num);
    bytes = bytes - strlen(a);
    for (i = 0; i < strlen(a); i = i + 1) {
      newstate = 0;
      if ((state == 0) && ((a[i] == "y") || (a[i] == "Y")))
        newstate = 1;
      if ((state == 1) && (a[i] == "e"))
        newstate = 2;
      if ((state == 2) && (a[i] == "s")) {
        # DEBUG display("hit ", a[i-2], a[i-1], a[i], "\n");
        num = num + 1;
        if (num >= max) return (num);
        newstate = 0;
      }
      state = newstate;
    }
  }
  # inconclusive result
  return (-1);
}

#
# This functions tests the vulnerability. "negotiate" indicates whether
# full telnet negotiation should be performed using telnet_init().
# Some targets might need it while others, like FreeBSD, fail to respond
# to AYT in an expected way when the negotiation is done (cf. comments
# accompanying count_ayt()).
#
# Local variables: r, total, size, bomb, succ
#

function attack(port, negotiate) {
  succ = 0;
  soc = open_sock_tcp(port);
  if (!soc) return (0);
  if (negotiate)
    # standard negotiation
    r = telnet_negotiate(socket:soc);
  else {
    # weird BSD magic, is is necessary?
    send(socket:soc, data:iac_will_naol);
    send(socket:soc, data:iac_will_encr);
    r = 1;
  }
  if (r) {
    # test whether the server talks to us at all
    # and whether AYT is supported
    send(socket:soc, data:iac_ayt);
    r = count_ayt(sock:soc, max:1);
    # DEBUG display("probe ", r, "\n");
    if (r >= 1) {
      # test whether too many AYT's make the server die
      total = 2048; size = total * strlen(iac_ayt);
      bomb = iac_ao + crap(length:size, data:iac_ayt);
      send(socket:soc, data:bomb);
      r = count_ayt(sock:soc, max:total);
      # DEBUG
#display("attack ", r, " expected ", total, "\n");
      if ((r >= 0) && (r < total)) succ = 1;
    }
  }
  close(soc);
  return (succ);
}

port = get_telnet_port(default:23);
success = attack(port:port, negotiate:0);
if (!success)
  success = attack(port:port, negotiate:1);

if (success)
  security_message(port:port);