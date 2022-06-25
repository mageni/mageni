##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat Reader DC (Classic Track) Multiple Vulnerabilities-apsb17-36 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812967");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-16377", "CVE-2017-16378", "CVE-2017-16360", "CVE-2017-16388",
		"CVE-2017-16389", "CVE-2017-16390", "CVE-2017-16393", "CVE-2017-16398",
		"CVE-2017-16381", "CVE-2017-16385", "CVE-2017-16392", "CVE-2017-16395",
		"CVE-2017-16396", "CVE-2017-16363", "CVE-2017-16365", "CVE-2017-16374",
		"CVE-2017-16384", "CVE-2017-16386", "CVE-2017-16387", "CVE-2017-16368",
		"CVE-2017-16383", "CVE-2017-16391", "CVE-2017-16410", "CVE-2017-16362",
		"CVE-2017-16370", "CVE-2017-16376", "CVE-2017-16382", "CVE-2017-16394",
		"CVE-2017-16397", "CVE-2017-16399", "CVE-2017-16400", "CVE-2017-16401",
		"CVE-2017-16402", "CVE-2017-16403", "CVE-2017-16404", "CVE-2017-16405",
		"CVE-2017-16408", "CVE-2017-16409", "CVE-2017-16412", "CVE-2017-16414",
		"CVE-2017-16417", "CVE-2017-16418", "CVE-2017-16420", "CVE-2017-11293",
		"CVE-2017-16407", "CVE-2017-16413", "CVE-2017-16415", "CVE-2017-16416",
		"CVE-2017-16361", "CVE-2017-16366", "CVE-2017-16369", "CVE-2017-16380",
		"CVE-2017-16419", "CVE-2017-16367", "CVE-2017-16379", "CVE-2017-16406",
		"CVE-2017-16364", "CVE-2017-16371", "CVE-2017-16372", "CVE-2017-16373",
		"CVE-2017-16375", "CVE-2017-16411", "CVE-2017-11307", "CVE-2017-11308",
                "CVE-2017-11240", "CVE-2017-11250", "CVE-2017-11306", "CVE-2017-11253");
  script_bugtraq_id(101821, 101818, 101831, 101824, 101816, 101823, 101819, 101812,
                    101830, 101820, 101814, 101817, 101815, 101813);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-06 12:23:24 +0530 (Tue, 06 Mar 2018)");
  script_name("Adobe Acrobat Reader DC (Classic Track) Multiple Vulnerabilities-apsb17-36 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat Reader
  DC (Classic Track) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Two access of uninitialized point vulnerabilities that could result in
    remote could execution,

  - Six use after free vulnerabilities that could result in remote code execution.

  - Five buffer access with incorrect length value vulnerabilities that could
    result in remote code execution.

  - Six buffer over-read vulnerabilities that could result in remote code
    execution.

  - A buffer overflow vulnerability that could result in remote code execution.

  - A heap overflow vulnerability that could result in remote code execution.

  - Two improper validation of array index vulnerabilities that could result
    in remote code execution.

  - Multiple out-of-bounds read vulnerabilities that could result in remote code
    execution.

  - Four out-of-bounds write vulnerabilities that could result in remote code
    execution.

  - Two security bypass vulnerabilities that could result in drive-by-downloads.

  - A security bypass vulnerability that could result in information disclosure.

  - A security bypass vulnerability that could result in remote code execution.

  - A stack exhaustion vulnerability that could result in excessive resource
    consumption.

  - Three type confusion vulnerabilities that could result in remote code
    execution.

  - Six untrusted pointer dereference vulnerabilities that could result in remote
    code execution.

  - For more details, refer the reference links mentioned.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application.
  Failed attacks may cause a denial-of-service condition. Also attackers will be
  able to gain access to potentially sensitive information, get excessive resource
  consumption and get unintentional download of malicious software.");

  script_tag(name:"affected", value:"Adobe Acrobat Reader DC (Classic Track)
  2015.006.30355 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC (Classic Track)
  version 2015.006.30392 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-36.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

##2015.006.30392 == 15.006.30392
if(version_is_less(version:vers, test_version:"15.006.30392"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"2015.006.30392", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
