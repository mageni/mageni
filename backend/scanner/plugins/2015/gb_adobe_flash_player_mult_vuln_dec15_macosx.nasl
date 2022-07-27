###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_dec15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities Dec15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806779");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049",
                "CVE-2015-8050", "CVE-2015-8418", "CVE-2015-8454", "CVE-2015-8455",
                "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058",
                "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062",
                "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066",
                "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070",
                "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403",
                "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407",
                "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411",
                "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415",
                "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8419", "CVE-2015-8420",
                "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424",
                "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428",
                "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432",
                "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436",
                "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440",
                "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444",
                "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448",
                "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452",
                "CVE-2015-8453", "CVE-2015-8456", "CVE-2015-8457", "CVE-2015-8652",
                "CVE-2015-8653", "CVE-2015-8654", "CVE-2015-8655", "CVE-2015-8656",
                "CVE-2015-8657", "CVE-2015-8822", "CVE-2015-8658", "CVE-2015-8820",
                "CVE-2015-8821", "CVE-2015-8823");
  script_bugtraq_id(78717, 78718, 78715, 78714, 78716, 78712, 78710, 78715, 78713);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-10 14:56:57 +0530 (Thu, 10 Dec 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities Dec15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple heap buffer overflow vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - Multiple security bypass vulnerabilities.

  - A stack overflow vulnerability.

  - A type confusion vulnerability.

  - An integer overflow vulnerability.

  - A buffer overflow vulnerability.

  - Multiple use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions and execute arbitrary code on the affected
  system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.268 and 19.x and 20.x before 20.0.0.228 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.268 or 20.0.0.228 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"20.0.0.227"))
{
  fix = "20.0.0.228";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.268"))
{
  fix = "18.0.0.268";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:' + fix + '\n';
  security_message(data:report);
  exit(0);
}
