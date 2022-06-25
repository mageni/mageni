###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_security_bypass_vuln_apr17_macosx.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Oracle Virtualbox Security Bypass Vulnerability - 01 Apr17 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811012");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2017-3538");
  script_bugtraq_id(97698);
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-25 15:31:17 +0530 (Tue, 25 Apr 2017)");
  script_name("Oracle Virtualbox Security Bypass Vulnerability - 01 Apr17 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Oracle VM
  VirtualBox and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  in the 'Shared Folder' component of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.0.34
  and prior to 5.1.16 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.0.34, 5.1.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.virtualbox.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(5\.0)")
{
  if(version_is_less(version:virtualVer, test_version:"5.0.34"))
  {
    fix = "5.0.34";
    VULN = TRUE;
  }
}

else if(virtualVer =~ "^(5\.1)")
{
  if(version_is_less(version:virtualVer, test_version:"5.1.16"))
  {
    fix = "5.1.16";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
