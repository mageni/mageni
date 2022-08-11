###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln02_apr15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Apr 2015 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805536");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-0491", "CVE-2015-0488", "CVE-2015-0480", "CVE-2015-0478",
                "CVE-2015-0477", "CVE-2015-0469", "CVE-2015-0460", "CVE-2015-0459");
  script_bugtraq_id(74094, 74111, 74104, 74147, 74119, 74072, 74097, 74083);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-21 16:34:06 +0530 (Tue, 21 Apr 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Apr 2015 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in the Java Cryptography Extension (JCE) subcomponent's RSA signature
  implementation.

  - An error in the JSSE subcomponent that is triggered when checking X.509
  certificate options.

  - An error in the 'ReferenceProcessor::process_discovered_references' function
  in share/vm/memory/referenceProcessor.cpp script.

  - Two unspecified errors related to the 2D subcomponent.

  - An error in the Beans subcomponent related to permissions and resource
  loading.

  - An off-by-one overflow condition in the functions
  'LigatureSubstitutionProcessor::processStateEntry' and
  'LigatureSubstitutionProcessor2::processStateEntry' within LigatureSubstProc.cpp
  and LigatureSubstProc2.cpp scripts respectively.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain knowledge of potentially sensitive information, conduct
  denial-of-service attacks, execute arbitrary code and other unspecified impact.");

  script_tag(name:"affected", value:"Oracle Java SE 5.0 update 81 and prior,
  6 update 91 and prior, 7 update 76 and prior, and 8 update 40 and prior on
  Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(jreVer =~ "^(1\.(8|7|6|5))")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.40")||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.76")||
     version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.91")||
     version_in_range(version:jreVer, test_version:"1.5.0", test_version2:"1.5.0.81"))
  {
    report = 'Installed version: ' + jreVer + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
