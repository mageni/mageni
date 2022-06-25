###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit Reader Multiple Vulnerabilities-Apr18 (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813156");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-14458", "CVE-2017-17557", "CVE-2018-10302", "CVE-2018-10303",
                "CVE-2018-10473", "CVE-2018-10474", "CVE-2018-10475", "CVE-2018-10476",
                "CVE-2018-10477", "CVE-2018-10478", "CVE-2018-10479", "CVE-2018-10480",
                "CVE-2018-10481", "CVE-2018-10482", "CVE-2018-10483", "CVE-2018-10484",
                "CVE-2018-10485", "CVE-2018-10486", "CVE-2018-10487", "CVE-2018-10488",
                "CVE-2018-10489", "CVE-2018-10490", "CVE-2018-10491", "CVE-2018-10492",
                "CVE-2018-10493", "CVE-2018-10494", "CVE-2018-10495", "CVE-2018-1173",
                "CVE-2018-1174", "CVE-2018-1175", "CVE-2018-1176", "CVE-2018-1177",
                "CVE-2018-1178", "CVE-2018-1179", "CVE-2018-1180", "CVE-2018-3842",
                "CVE-2018-3843", "CVE-2018-3850", "CVE-2018-3853", "CVE-2018-5674",
                "CVE-2018-5675", "CVE-2018-5676", "CVE-2018-5677", "CVE-2018-5678",
                "CVE-2018-5679", "CVE-2018-5680", "CVE-2018-7407", "CVE-2018-9935",
                "CVE-2018-9936", "CVE-2018-9937", "CVE-2018-9938", "CVE-2018-9939",
                "CVE-2018-9940", "CVE-2018-9941", "CVE-2018-9942", "CVE-2018-9943",
                "CVE-2018-9944", "CVE-2018-9945", "CVE-2018-9946", "CVE-2018-9947",
                "CVE-2018-9948", "CVE-2018-9949", "CVE-2018-9950", "CVE-2018-9951",
                "CVE-2018-9952", "CVE-2018-9953", "CVE-2018-9954", "CVE-2018-9955",
                "CVE-2018-9956", "CVE-2018-9957", "CVE-2018-9958", "CVE-2018-9959",
                "CVE-2018-9960", "CVE-2018-9961", "CVE-2018-9962", "CVE-2018-9963",
                "CVE-2018-9964", "CVE-2018-9965", "CVE-2018-9966", "CVE-2018-9967",
                "CVE-2018-9968", "CVE-2018-9969", "CVE-2018-9970", "CVE-2018-9971",
                "CVE-2018-9972", "CVE-2018-9973", "CVE-2018-9974", "CVE-2018-9975",
                "CVE-2018-9976", "CVE-2018-9977", "CVE-2018-9978", "CVE-2018-9979",
                "CVE-2018-9980", "CVE-2018-9981", "CVE-2018-9982", "CVE-2018-9983",
                "CVE-2018-9984", "CVE-2018-3924", "CVE-2018-3939", "CVE-2018-17623");
  script_bugtraq_id(105602);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-25 14:35:06 +0530 (Wed, 25 Apr 2018)");
  script_name("Foxit Reader Multiple Vulnerabilities-Apr18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error where the application passes an insufficiently qualified path in
    loading an external library when a user launches the application.

  - A heap buffer overflow error.

  - Multiple use-after-free errors.

  - The use of uninitialized new 'Uint32Array' object or member variables in
    'PrintParams' or 'm_pCurContex' objects.

  - An incorrect memory allocation, memory commit, memory access, or array access.

  - Type Confusion errors.

  - An error in 'GoToE' & 'GoToR' Actions.

  - An out-of-bounds read error in the '_JP2_Codestream_Read_SOT' function.

  - An error since the application did not handle a COM object properly.

  - An error allowing users to embed executable files.

  - U3D out-of-bounds read, write and access errors.

  - U3D uninitialized pointer error.

  - U3D heap buffer overflow or stack-based buffer overflow error.

  - An error when the application is not running in safe-reading-mode and can
    be abused via '_JP2_Codestream_Read_SOT' function.

  - U3D Type Confusion errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, execute arbitrary code and
  gain access to sensitive data from memory.");

  script_tag(name:"affected", value:"Foxit Reader versions 9.0.1.1049 and prior on windows");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 9.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");
  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1040733");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

## 9.1 == 9.1.0.5096
if(version_is_less(version:pdfVer, test_version:"9.1.0.5096"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.1", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);