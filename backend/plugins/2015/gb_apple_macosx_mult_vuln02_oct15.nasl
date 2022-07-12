###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_oct15.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-02 October-15
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806154");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2015-7761", "CVE-2015-7760", "CVE-2015-5922", "CVE-2015-5917",
                "CVE-2015-5915", "CVE-2015-5914", "CVE-2015-5913", "CVE-2015-5902",
                "CVE-2015-5901", "CVE-2015-5900", "CVE-2015-5897", "CVE-2015-5894",
                "CVE-2015-5893", "CVE-2015-5891", "CVE-2015-5890", "CVE-2015-5889",
                "CVE-2015-5888", "CVE-2015-5887", "CVE-2015-5884", "CVE-2015-5883",
                "CVE-2015-5878", "CVE-2015-5877", "CVE-2015-5875", "CVE-2015-5873",
                "CVE-2015-5872", "CVE-2015-5871", "CVE-2015-5870", "CVE-2015-5866",
                "CVE-2015-5865", "CVE-2015-5864", "CVE-2015-5854", "CVE-2015-5853",
                "CVE-2015-5849", "CVE-2015-5836", "CVE-2015-5833", "CVE-2015-5830",
                "CVE-2015-3785");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:24:34 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 October-15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files, execute arbitrary code with system privilege.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.6.8 through
  10.11");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205267");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Sep/msg00008.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([6-9|10)\.");
  script_xref(name:"URL", value:"https://www.apple.com");

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
  if(version_in_range(version:osVer, test_version:"10.6.8", test_version2:"10.10.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);