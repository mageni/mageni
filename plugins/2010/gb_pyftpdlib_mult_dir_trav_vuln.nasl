###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_mult_dir_trav_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# pyftpdlib FTP Server Multiple Directory Traversal Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801616");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2008-7262");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("pyftpdlib FTP Server Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/issues/detail?id=55");
  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  script_mandatory_keys("pyftpdlib/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to retrieve or upload arbitrary
  system files.");
  script_tag(name:"affected", value:"ftpserver.py in pyftpdlib before 0.3.0");
  script_tag(name:"insight", value:"The flaws exist because pyftpdlib allow remote authenticated users to access
  arbitrary files and directories via vectors involving a symlink in a pathname
  to a CWD, DELE, STOR, or RETR command.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to pyftpdlib version 0.5.2 or later.");
  script_tag(name:"summary", value:"This host is running pyftpdlib FTP server and is prone to multiple
  directory traversal vulnerabilities.");

  script_xref(name:"URL", value:"http://code.google.com/p/pyftpdlib/downloads/list");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  if(version_is_less(version:ver, test_version:"0.3.0")) {
     security_message(port:0);
  }
}
