###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 September-2016
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807888");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-4694", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5770",
                "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773", "CVE-2016-6174",
                "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291",
                "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296",
                "CVE-2016-6297", "CVE-2016-4697", "CVE-2016-4696", "CVE-2016-4698",
                "CVE-2016-4699", "CVE-2016-4700", "CVE-2016-4701", "CVE-2016-4779",
                "CVE-2016-4702", "CVE-2016-4703", "CVE-2016-4706", "CVE-2016-4707",
                "CVE-2016-4708", "CVE-2016-4711", "CVE-2016-4712", "CVE-2016-4713",
                "CVE-2016-0755", "CVE-2016-4715", "CVE-2016-4716", "CVE-2016-4717",
                "CVE-2016-4718", "CVE-2016-4722", "CVE-2016-4723", "CVE-2016-4724",
                "CVE-2016-4725", "CVE-2016-4726", "CVE-2016-4727", "CVE-2016-4745",
                "CVE-2016-4771", "CVE-2016-4772", "CVE-2016-4773", "CVE-2016-4774",
                "CVE-2016-4776", "CVE-2016-4775", "CVE-2016-4777", "CVE-2016-4778",
                "CVE-2016-4736", "CVE-2016-4658", "CVE-2016-5131", "CVE-2016-4738",
                "CVE-2016-4739", "CVE-2016-4742", "CVE-2016-4748", "CVE-2016-4750",
                "CVE-2016-4752", "CVE-2016-4753", "CVE-2016-4755", "CVE-2016-4709",
                "CVE-2016-4710");
  script_bugtraq_id(93063, 91396, 92074, 92073, 93054, 93055, 92095, 92094, 92097,
                    93059, 92078, 92053, 91732, 91399, 91398, 91397, 92099, 82307,
                    92111, 91403, 92115, 91401, 93060, 93056);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-28 12:22:55 +0530 (Wed, 28 Sep 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 September-2016");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.7.5 through 10.11.x
  prior to 10.12");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12 or later. Please see the references for more information.

  Note: According to the vendor an upgrade to version 10.12 is required to
  mitigate this vulnerabilities. Please see the advisory (HT207170) for more info.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207170");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([7-9]|1[01])");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.([7-9]|1[01])"){
  if(version_in_range(version:osVer, test_version: "10.7.5", test_version2:"10.11.6")){
    report = report_fixed_ver(installed_version:osVer, fixed_version:"According to the vendor an upgrade to version 10.12 is required to mitigate this vulnerabilities. Please see the advisory (HT207170) for more info.");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);