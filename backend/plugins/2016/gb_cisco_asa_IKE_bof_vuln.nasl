###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_IKE_bof_vuln.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Cisco ASA Software IKEv1 and IKEv2 Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.806682");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2016-1287");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-11 14:20:25 +0530 (Thu, 11 Feb 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA Software IKEv1 and IKEv2 Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco ASA Software and
  is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to buffer overflow error in the
  Internet Key Exchange (IKE) version 1 (v1) and IKE version 2 (v2) code.");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker to
  execute arbitrary code and obtain full control of the system or to cause a reload
  of the affected system.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 7.2.x, 8.0.x,
  8.1.x, 8.3.x, 8.6.x before 9.1(6.11), 8.2.x before 8.2(5.59), 8.4.x before
  8.4(7.30), 8.7.x before 8.7(1.18), 9.0 before 9.0(4.38), 9.1 before 9.1(6.11),
  9.2 before 9.2(4.5), 9.3 before 9.3(3.7), 9.4 before 9.4(2.4), 9.5 before
  9.5(2.2) on Cisco ASA 5500 Series Adaptive Security Appliances, Cisco ASA 5500-X
  Series Next-Generation Firewalls, Cisco ASA Services Module for Cisco Catalyst
  6500 Series Switches and Cisco 7600 Series Routers, Cisco ASA 1000V Cloud Firewall,
  Cisco Adaptive Security Virtual Appliance (ASAv), Cisco Firepower 9300 ASA Security
  Module, Cisco ISA 3000 Industrial Security Appliance.");

  script_tag(name:"solution", value:"Upgrade to 8.4(7.30) or 8.2(5.59)
  or 8.7(1.18) or 9.0(4.38) or 9.1(6.11) or 9.2(4.5) or 9.3(3.7) or 9.4(2.4) or
  9.5(2.2).");

  script_tag(name:"solution_type", value:"VendorFix");

# 2016-06-13: 404
#  script_xref(name:"URL", value:"https://blog.exodusintel.com/2016/01/26/firewall-hacking");
  script_xref(name:"URL", value:"http://www.cisco.com/web/software/280775065/45357/ASA-825-Interim-Release-Notes.html");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!cisVer = get_app_version(cpe: CPE, nofork: TRUE)){
  exit(0);
}

##Replace parenthesis with .
cisVer = ereg_replace(string:cisVer, pattern:"\(([0-9.]+)\)", replace:".\1");

if(cisVer =~ "^(7\.2)|^(8\.0)|^(8\.1)|^(8\.3)|^(8\.6)")
{
    fix = "9.1(6.11)";
    VULN = TRUE;
}

else if(cisVer =~ "^(8\.2)")
{
  if(version_is_less(version:cisVer, test_version:"8.2.5.59)"))
  {
    fix = "8.2(5.59)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(8\.4)")
{
  if(version_is_less(version:cisVer, test_version:"8.4.7.30"))
  {
    fix = "8.4(7.30)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(8\.7)")
{
  if(version_is_less(version:cisVer, test_version:"8.7.1.18"))
  {
    fix = "8.7(1.18)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.0)")
{
  if(version_is_less(version:cisVer, test_version:"9.0.4.38"))
  {
    fix = "9.0(4.38)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.1)")
{
  if(version_is_less(version:cisVer, test_version:"9.1.6.11"))
  {
    fix = "9.1(6.11)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.2)")
{
  if(version_is_less(version:cisVer, test_version:"9.2.4.5"))
  {
    fix = "9.2(4.5)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.3)")
{
  if(version_is_less(version:cisVer, test_version:"9.3.3.7"))
  {
    fix = "9.3(3.7)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.4)")
{
  if(version_is_less(version:cisVer, test_version:"9.4.2.4"))
  {
    fix = "9.4(2.4)";
    VULN = TRUE;
  }
}

else if(cisVer =~ "^(9\.5)")
{
  if(version_is_less(version:cisVer, test_version:"9.5.2.2"))
  {
    fix = "9.5(2.2)";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:cisVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
