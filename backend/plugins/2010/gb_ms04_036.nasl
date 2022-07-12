###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms04_036.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Windows NT NNTP Component Buffer Overflow
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100608");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-26 19:54:51 +0200 (Mon, 26 Apr 2010)");
  script_cve_id("CVE-2004-0574");

  script_name("Windows NT NNTP Component Buffer Overflow");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms04-036.mspx");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "nntpserver_detect.nasl");
  script_require_ports("Services/nntp", 119);
  script_tag(name:"solution", value:"Microsoft has released a bulletin that includes fixes to address this
issue for supported versions of the operating system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The Network News Transfer Protocol (NNTP) component of Microsoft
Windows NT Server 4.0, Windows 2000 Server, Windows Server 2003,
Exchange 2000 Server, and Exchange Server 2003 allows remote attackers
to execute arbitrary code via XPAT patterns, possibly related to
improper length validation and an unchecked buffer, leading to
off-by-one and heap-based buffer overflows.");
  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/nntp");
if(!port)port = 119;
if(!get_port_state(port))exit(0);

banner = get_kb_item(string("nntp/banner/", port));
if(!banner || "200 NNTP Service" >!< banner)exit(0);

version = eregmatch(pattern:"^200 NNTP Service .* Version: ([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

VULN = FALSE;

if(version[1] =~ "^5\.5\.") {
  if(version_is_less(version: version[1], test_version:"5.5.1877.79"))  {
   VULN = TRUE;
  }
}

else if(version[1] =~ "^5\.0\.") {
  if(version_is_less(version: version[1], test_version:"5.0.2195.6972")) {
    VULN = TRUE;
  }
}

else if(version[1] =~ "^6\.0\.") {
  if(version_is_less(version: version[1], test_version:"6.0.3790.206")) {
    VULN = TRUE;
  }
}

if(VULN) {
  security_message(port:port);
  exit(0);
}

exit(0);
