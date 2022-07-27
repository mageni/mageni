###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_auth_bypass_vuln.nasl 2013-12-31 17:01:32Z dec$
#
# Apple Mac OS X Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804184");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2013-5163");
  script_bugtraq_id(62812);
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-31 20:51:30 +0530 (Tue, 31 Dec 2013)");
  script_name("Apple Mac OS X Authentication Bypass Vulnerability");
  script_tag(name:"summary", value:"This host is running Apple Mac OS X and is prone to authentication bypass
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Run Mac Updates and install OS X v10.8.5 Supplemental Update.");
  script_tag(name:"insight", value:"The flaw is due to a logic error in the way the program verifies
authentication credentials.");
  script_tag(name:"affected", value:"Mac OS X version 10.8.5 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to bypass password
validation.");
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5964");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123506/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.8");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5964");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  exit(99);
}

exit(0);