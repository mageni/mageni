# OpenVAS Vulnerability Test
# $Id: DDI_warftpd_cwd_overflow.nasl 13499 2019-02-06 12:55:20Z cfischer $
# Description: War FTP Daemon CWD/MKD Buffer Overflow
#
# Authors:
# Erik Tayler <erik@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense, Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11205");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(966);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0131");
  script_name("War FTP Daemon CWD/MKD Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Digital Defense, Inc.");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/war_ftpd/detected");

  script_xref(name:"URL", value:"ftp://ftp.jgaa.com/pub/products/Windows/WarFtpDaemon/");

  script_tag(name:"solution", value:"Visit the referenced link and download the latest version of WarFTPd.");

  script_tag(name:"summary", value:"The version of the War FTP Daemon running on this host is vulnerable to a
  buffer overflow attack. This is due to improper bounds checking within the code that handles both the CWD
  and MKD commands.");

  script_tag(name:"impact", value:"By exploiting this vulnerability, it is possible to crash the server, and
  potentially run arbitrary commands on this system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
r = get_ftp_banner(port:port);
if(!r)exit(0);

if("WAR-FTPD 1.66x4" >< r || "WAR-FTPD 1.67-03" >< r) {
  security_message(port:port);
}

exit(0);