# OpenVAS Vulnerability Test
# $Id: ssh_scp.nasl 13568 2019-02-11 10:22:27Z cfischer $
# Description: scp File Create/Overwrite
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11339");
  script_version("$Revision: 13568 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1742);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2000-0992");
  script_name("scp File Create/Overwrite");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"solution", value:"Patch and new version are available from SSH/OpenSSH.");

  script_tag(name:"summary", value:"You are running OpenSSH 1.2.3, or 1.2.");

  script_tag(name:"insight", value:"This version has directory traversal vulnerability in scp, it allows
  a remote malicious scp server to overwrite arbitrary files via a .. (dot dot) attack.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default:22);
banner = get_ssh_server_banner(port:port);
if ( ! banner ) exit(0);

#Looking for OpenSSH product version number 1.2 and 1.2.3
if(ereg(pattern:".*openssh[-_](1\.2($|\.3|[^0-9])).*",string:banner, icase:TRUE))
  security_message(port:port);

if(ereg(pattern:".*ssh-.*-1\.2\.(1[0-4]|2[0-7])[^0-9]", string:banner, icase:TRUE))
  security_message(port:port);
