###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_mult_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# pyftpdlib FTP Server Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801613");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3494", "CVE-2009-5012", "CVE-2009-5013", "CVE-2009-5011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("pyftpdlib FTP Server Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=100");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=104");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=105");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=114");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=119");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  script_mandatory_keys("pyftpdlib/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");
  script_tag(name:"affected", value:"ftpserver.py in pyftpdlib before 0.5.2");
  script_tag(name:"insight", value:"- Race condition in the FTPHandler class allows remote attackers to cause a
    denial of service by establishing and then immediately closing a TCP
    connection.

  - Improper permission check for the NLST command allows remote authenticated
    users to bypass intended access restrictions and list the root directory via
    an FTP session.

  - Memory leak in the on_dtp_close function allows remote authenticated users
    to cause a denial of service by sending a QUIT command during a data transfer.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to pyftpdlib version 0.5.2 or later.");
  script_tag(name:"summary", value:"This host is running pyftpdlib FTP server and is prone to multiple
  vulnerabilities.");

  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/downloads/list");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  if(version_is_less(version:ver, test_version:"0.5.2")) {
     security_message(port:0);
  }
}
