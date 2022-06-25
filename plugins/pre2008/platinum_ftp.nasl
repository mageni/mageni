# OpenVAS Vulnerability Test
# $Id: platinum_ftp.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: Platinum FTP Server
#
# Authors:
# Douglas Minderhout <dminderhout@layer3com.com>
# Based on a previous script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2003 Douglas Minderhout
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

# Thanks to: H D Moore
# Ref:
# Message-ID: <1043650912.3e34d960788ac@webmail.web-sale.dk>
# Date: Mon, 27 Jan 2003 08:01:52 +0100
# Subject: [VulnWatch] Multiple vulnerabilities found in PlatinumFTPserver V1.0.7

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11200");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Platinum FTP Server");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2003 Douglas Minderhout");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/platinum/ftp/detected");

  script_tag(name:"solution", value:"Update to the latest version of this FTP server.");

  script_tag(name:"summary", value:"Platinum FTP server for Win32 has several vulnerabilities in
  the way it checks the format of command strings passed to it.");

  script_tag(name:"insight", value:"The flaws leads to the following vulnerabilities in the server:

  The 'dir' command can be used to examine the filesystem of the machine and
  gather further information about the host by using relative directory listings
  (I.E. '../../../' or '\..\..\..').

  The 'delete' command can be used to delete any file on the server that the
  Platinum FTP server has permissions to.

  Issuing the command  'cd @/..@/..' will cause the
  Platinum FTP server to crash and consume all available CPU time on
  the server.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port: port);
if(banner) {
  if(egrep(pattern:"^220.*PlatinumFTPserver V1\.0\.[0-7][^0-9].*$",string:banner)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);