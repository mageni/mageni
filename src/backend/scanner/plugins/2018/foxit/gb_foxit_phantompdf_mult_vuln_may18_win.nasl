###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit PhantomPDF Multiple Vulnerabilities-May18 (Windows)
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813196");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-17557", "CVE-2017-14458", "CVE-2018-3842", "CVE-2018-3853",
                "CVE-2018-3850", "CVE-2018-10303", "CVE-2018-10302", "CVE-2018-3843");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-18 12:43:57 +0530 (Fri, 18 May 2018)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities-May18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An unsafe DLL loading as application passes an insufficiently qualified path
    in loading an external library when a user launches the application.

  - An out-of-bounds read and write error.

  - A type confusion error while executing certain XFA functions in crafted PDF
    files since the application could transform non-CXFA_Object to CXFA_Object
    without judging the data type and use the discrepant CXFA_Object to get layout
    object directly.

  - An unspecified error in GoToE & GoToR Actions.

  - The application is not running in Safe-Reading-Mode and can be abused via
    '_JP2_Codestream_Read_SOT' function.

  - An error as application do not handle a COM object properly.

  - A use-after-free error as the application could continue to traverse pages
    after the document has been closed or free certain objects repeatedly.

  - Uninitialized memory or pointer error due to the use of uninitialized new
    'Uint32Array' object or member variables in 'PrintParams' or 'm_pCurContex'
    objects.

  - A use-after-free error due to the use of freed object when executing JavaScript
    or invoking certain functions to get object properties.

  - A use-after-free error due to the use of object which has been closed or removed.

  - A type confusion error when parsing files with associated file annotations due
    to deference of an object of invalid type.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, execute arbitrary code and
  gain access to sensitive data from memory.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 8.3.5.30351 and
  earlier on windows");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 8.3.6
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

## 8.3.6 == 8.3.6.35572
if(version_is_less(version:pdfVer, test_version:"8.3.6.35572"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"8.3.6", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
