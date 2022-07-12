###############################################################################
# OpenVAS Vulnerability Test
# $Id: TurboFTP_37726.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# TurboFTP 'DELE' FTP Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100448");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-01-14 12:06:50 +0100 (Thu, 14 Jan 2010)");
  script_bugtraq_id(37726);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("TurboFTP 'DELE' FTP Command Remote Buffer Overflow Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/turboftp/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"TurboFTP is prone to a remote buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"TurboFTP 1.00.712 is vulnerable. Prior versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37726");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-004-turboftp-server-1-00-712-dos/");
  script_xref(name:"URL", value:"http://www.turboftp.com/");
  script_xref(name:"URL", value:"http://www.tbsoftinc.com/tbserver/turboftp-server-releasenotes.htm");
  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_ftp_port(default:21);
ftpbanner = get_ftp_banner(port:ftpPort);
if(! banner || "TurboFTP" >!< ftpbanner)
  exit(0);

version = eregmatch(pattern: "220 TurboFTP Server ([0-9.]+)", string: ftpbanner);
if(isnull(version[1]))
  exit(0);

if(version_is_equal(version: version[1], test_version: "1.00.712")) {
  security_message(port: ftpPort);
  exit(0);
}

exit(99);