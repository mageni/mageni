# OpenVAS Vulnerability Test
# Description: Subversion SVN Protocol Parser Remote Integer Overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12284");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10519);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2004-0413");
  script_name("Subversion SVN Protocol Parser Remote Integer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/subversion", 3690);

  script_tag(name:"solution", value:"Upgrade to version 1.0.5 or newer.");

  script_tag(name:"summary", value:"A remote overflow exists in Subversion. svnserver fails to validate
  svn:// requests resulting in a heap overflow.");

  script_tag(name:"impact", value:"With a specially crafted request, an attacker can cause arbitrary code
  execution resulting in a loss of integrity.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:3690, proto:"subversion");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = recv_line(socket:soc, length:1024);
if(!r) {
  close(soc);
  exit(0);
}

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/VT-Testr0x ) ");
send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);
close(soc);
if(!r)
  exit(0);

if(egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*")) {
  security_message(port:port);
  exit(0);
}

exit(99);