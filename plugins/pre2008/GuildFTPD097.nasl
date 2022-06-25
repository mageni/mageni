# OpenVAS Vulnerability Test
# $Id: GuildFTPD097.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: GuildFTPd Directory Traversal
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
# (slightly modified by rd)
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10694");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2789);
  script_cve_id("CVE-2001-0767");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("GuildFTPd Directory Traversal");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/guildftpd/detected");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5CP0S2A4AU.html");

  script_tag(name:"solution", value:"Upgrade your FTP server.");

  script_tag(name:"summary", value:"Version 0.97 of GuildFTPd was detected. A security vulnerability in
  this product allows anyone with a valid FTP login to read arbitrary files on the system.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(!banner)exit(0);

if ("GuildFTPD FTP" >< banner)
{
  if ("Version 0.97" >< banner)
  {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);