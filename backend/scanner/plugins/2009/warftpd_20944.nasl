###############################################################################
# OpenVAS Vulnerability Test
# $Id: warftpd_20944.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# WarFTPD Multiple Format String Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100282");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_bugtraq_id(20944);
  script_cve_id("CVE-2006-5789");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("WarFTPD Multiple Format String Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20944");
  script_xref(name:"URL", value:"http://support.jgaa.com/index.php?MenuPage=product");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/450804");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/war_ftpd/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"WarFTPd is prone to multiple remote format-string vulnerabilities
  because the application fails to sanitize user-supplied input before passing it to a formatted-output function.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to crash the server and possibly
  to execute arbitrary code within the context of the server, but this has not been confirmed.");

  script_tag(name:"affected", value:"WarFTPd 1.82.00-RC11 is reported vulnerable. Prior versions may be
  vulnerable as well.");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(!banner || "WarFTPd" >!< banner)
  exit(0);

if(!version = eregmatch(string: banner, pattern:"WarFTPd ([0-9.]+[-RC0-9]*)"))exit(0);
version[1] = ereg_replace(pattern:"-", string:version[1], replace:".");

if(version_is_equal(version: version[1], test_version:"1.82.00.RC11") ||
   version_is_equal(version: version[1], test_version:"1.82.00.RC12")) {
  security_message(port:port);
  exit(0);
}

exit(99);