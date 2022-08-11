###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openttd_mult_sec_bypass_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# OpenTTD Multiple Security bypass vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801206");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_bugtraq_id(39874);
  script_cve_id("CVE-2010-0401", "CVE-2010-0402", "CVE-2010-0406");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("OpenTTD Multiple Security bypass vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39669");
  script_xref(name:"URL", value:"http://security.openttd.org/en/CVE-2010-0401");
  script_xref(name:"URL", value:"http://security.openttd.org/en/CVE-2010-0402");
  script_xref(name:"URL", value:"http://security.openttd.org/en/CVE-2010-0406");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions and cause Denial of Service.");
  script_tag(name:"affected", value:"OpenTTD 1.0 and prior.");
  script_tag(name:"insight", value:"The flaws are due to

  - error in the handling of password requests which accepts a company
    password for authentication in response to a request for the server
    password.

  - A file descriptor leak can be exploited to crash the server by performing
    incomplete downloads of the map.

  - Improper validation of index values of certain items.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of OpenTTD 1.0.1 or later.");
  script_tag(name:"summary", value:"This host is installed with OpenTTD and is prone to multiple
  security bypass vulnerabilities.");
  script_xref(name:"URL", value:"http://www.openttd.org");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenTTD";
ver = registry_get_sz(key:key, item:"DisplayVersion");

if(ver)
{
  if(version_is_less(version: ver, test_version: "1.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
