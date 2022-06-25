###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_psd_integer_overflow_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# XnView PSD Record Type Parsing Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802443");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0684", "CVE-2012-0685");
  script_bugtraq_id(51546);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-24 14:02:14 +0530 (Tue, 24 Jul 2012)");
  script_name("XnView PSD Record Type Parsing Integer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47600/");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/msvr/msvr12-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on the
  system or cause a denial of service condition.");
  script_tag(name:"affected", value:"XnView versions 1.98.2 and prior on windows");
  script_tag(name:"solution", value:"Update to XnView version 1.98.5 or later.");
  script_tag(name:"summary", value:"This host has XnView installed and is prone to multiple integer
  overflow vulnerabilities.

  Vulnerabilities Insight:
  The flaws are due to integer overflow errors within the parsing of PSD
  record types and can be exploited to cause buffer overflows via a specially
  crafted PSD image.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.xnview.com/");
  exit(0);
}


include("version_func.inc");

xnviewVer = get_kb_item("XnView/Win/Ver");
if(isnull(xnviewVer)){
  exit(0);
}

if(version_is_less_equal(version:xnviewVer, test_version:"1.98.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
