###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln_HT208144.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-HT208144
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811790");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-7084", "CVE-2017-7074", "CVE-2017-7143", "CVE-2017-7083",
                "CVE-2017-0381", "CVE-2017-7138", "CVE-2017-7121", "CVE-2017-7122",
                "CVE-2017-7123", "CVE-2017-7124", "CVE-2017-7125", "CVE-2017-7126",
                "CVE-2017-11103", "CVE-2017-7077", "CVE-2017-7119", "CVE-2017-7114",
                "CVE-2017-7086", "CVE-2017-1000373", "CVE-2016-9063", "CVE-2017-9233",
                "CVE-2017-7141", "CVE-2017-7078", "CVE-2017-6451", "CVE-2017-6452",
                "CVE-2017-6455", "CVE-2017-6458", "CVE-2017-6459", "CVE-2017-6460",
                "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464", "CVE-2016-9042",
                "CVE-2017-7082", "CVE-2017-7080", "CVE-2017-10989", "CVE-2017-7128",
                "CVE-2017-7129", "CVE-2017-7130", "CVE-2017-7127", "CVE-2016-9840",
                "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");
  script_bugtraq_id(999551, 97074, 99276, 95131, 97049, 99502, 97078, 97076, 99177,
                    97058, 94337, 97045, 95248, 97046, 97052, 97050, 97051);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-26 12:22:46 +0530 (Tue, 26 Sep 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-HT208144");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple issues in zlib, SQLite, ntp, expat and files.

  - Multiple memory corruption issues.

  - A certificate validation issue existed in the handling of revocation data.

  - Window management, memory consumption and validation issues.

  - An encryption issue existed in the handling of mail drafts.

  - Turning off 'Load remote content in messages' did not apply to all mailboxes.

  - A resource exhaustion issue in 'glob' function.

  - A permissions issue existed in the handling of the Apple ID.

  - An out-of-bounds read error.

  - The security state of the captive portal browser was not obvious.

  - An upgrade issue existed in the handling of firewall settings.

  - Some unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause a denial of service, read unencrypted  password over the network, gain
  access to potentially sensitive information, determine the Apple ID of the owner
  of the computer, impersonate a service, execute arbitrary code with system
  privileges, execute arbitrary code with kernel privileges, able to intercept
  mail contents, revoked certificate to be trusted and have other unknown impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.8 through 10.12.x
  prior to 10.13");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13 or later.  Note: According to the vendor an upgrade to version 10.13 is required to
  mitigate this vulnerabilities. Please see the advisory (HT208144) for more info.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208144");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(8|9|10|11|12)");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer =~ "^10\.(8|9|10|11|12)"){
  if(version_in_range(version:osVer, test_version:"10.8", test_version2:"10.12.9")){
    report = report_fixed_ver(installed_version:osVer, fixed_version:"According to the vendor an upgrade to version 10.13 is required to mitigate this vulnerabilities. Please see the advisory (HT208144) for more info.");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);