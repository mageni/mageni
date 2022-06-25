###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_security_bypass_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Cisco ASA Challenge-Response Tunnel Group Selection Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806686");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2014-8023");
  script_bugtraq_id(72618);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-18 12:33:59 +0530 (Thu, 18 Feb 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA Challenge-Response Tunnel Group Selection Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco ASA Software and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper implementation of
  the tunnel group selection when a user authenticates to the remote access VPN
  via the challenge-response mechanism.");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker to
  bypass the tunnel group restriction and authenticate to a different tunnel group
  than the one selected during the authentication phase.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 8.2.x, 8.3.x, 8.4.x
  before 8.4(7.27), 8.6.x, 9.0.x before 9.0(4.34), 9.1.x before 9.1(5.100) and 9.2.x
  before 9.2(2.100).");

  script_tag(name:"solution", value:"Upgrade to Cisco ASA Software version 8.4(7.27)
  or 9.0(4.34) or 9.1(5.100) or 9.2(2.100) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCtz48533");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37489");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  script_xref(name:"URL", value:"http://www.cisco.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!cisVer = get_app_version(cpe: CPE, nofork: TRUE)){
  exit(0);
}

##Replace parenthesis with .
cisVer = ereg_replace(string:cisVer, pattern:"\(([0-9.]+)\)", replace:".\1");

if(cisVer =~ "^(8\.2)|^(8\.3)|^(8\.4)")
{
  if(version_is_less(version:cisVer, test_version:"8.4.7.27"))
  {
    fix = "8.4(7.27)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(8\.6)|^(9\.0)")
{
  if(version_is_less(version:cisVer, test_version:"9.0.4.34"))
  {
    fix = "9.0(4.34)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.1)")
{
  if(version_is_less(version:cisVer, test_version:"9.1.5.100"))
  {
    fix = "9.1(5.100)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.2)")
{
  if(version_is_less(version:cisVer, test_version:"9.2.2.100"))
  {
    fix = "9.2(2.100)";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:cisVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
