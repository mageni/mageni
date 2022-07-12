###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_auth_agent_auth_bypass_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# RSA Authentication Agent Authentication Bypass Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:emc:rsa_authentication_agent";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803749");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0931");
  script_bugtraq_id(58248);
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-28 11:21:00 +0530 (Wed, 28 Aug 2013)");
  script_name("RSA Authentication Agent Authentication Bypass Vulnerability (Windows)");


  script_tag(name:"summary", value:"The host is installed with RSA Authentication Agent and is prone to
authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 7.1.2 or later.");
  script_tag(name:"insight", value:"The flaw is triggered when a session is activated from the active screensaver
after the Quick PIN Unlock timeout has expired, which will result in an
incorrect prompt for a PIN as opposed to a prompt for the full passcode.");
  script_tag(name:"affected", value:"RSA Authentication Agent version 7.1.x before 7.1.2 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to bypass certain security
restrictions and gain unauthorized privileged access.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1028230");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438433.php");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120606");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/att-0/ESA-2013-012.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-03/att-0001/ESA-2013-012.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgent6432/Installed");
  script_xref(name:"URL", value:"http://www.rsa.com/node.aspx?id=2575");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

rasAutVer = get_app_version(cpe:CPE);
if(rasAutVer && rasAutVer =~ "^7\.1")
{
  if(version_is_less(version:rasAutVer, test_version:"7.1.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
