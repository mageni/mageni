###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_mult_unspecified_vuln_jan17_win.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# Oracle Virtualbox Multiple Unspecified Vulnerabilities - 01 Jan17 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810509");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2017-3316", "CVE-2017-3332", "CVE-2017-3290", "CVE-2016-5545");
  script_bugtraq_id(95579, 95599, 95601, 95590);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-19 10:28:03 +0530 (Thu, 19 Jan 2017)");
  script_name("Oracle Virtualbox Multiple Unspecified Vulnerabilities - 01 Jan17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Oracle VM
  VirtualBox and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws rae due to multiple
  unspecified errors in sub components 'GUI', 'VirtualBox SVGA Emulation'
  and 'Shared Folder'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.0.32
  and prior to 5.1.14 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  5.0.32 or 5.1.14 or later on Windows.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
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
  if(version_is_less(version:virtualVer, test_version:"5.0.32"))
  {
    fix = "5.0.32";
    VULN = TRUE;
  }
}

else if(virtualVer =~ "^(5\.1)")
{
  if(version_is_less(version:virtualVer, test_version:"5.1.14"))
  {
    fix = "5.1.14";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
