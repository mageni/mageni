# OpenVAS Vulnerability Test
# $Id: eftp_root_disclosure.nasl 13610 2019-02-12 15:17:00Z cfischer $
# Description: EFTP installation directory disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11093");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3331, 3333);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1109");
  script_name("EFTP installation directory disclosure ");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login");

  script_tag(name:"solution", value:"Update your FTP server.");

  script_tag(name:"summary", value:"The remote FTP server can be used to determine the
  installation directory by sending a request on an unexisting file.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more knowledge about
  this host, such as its filesystem layout.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

port = get_ftp_port(default:21);

soc = open_sock_tcp(port);
if(! soc) exit(0);

if( ftp_authenticate(socket:soc, user:login, pass:pass))
{
  for (i = 0; i < 2; i++)
  {
    vt_strings = get_vt_strings();
    req = string(cmd[i], " ", vt_strings["lowercase_rand"], "\r\n");
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
    if (egrep(string:r, pattern:" '[C-Z]:\\'"))
    {
      security_message(port);
      ftp_close(socket:soc);
      exit(0);
    }
  }
}
