###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit PhantomPDF Multiple Vulnerabilities-Nov18 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814156");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-17706", "CVE-2018-17691", "CVE-2018-17692", "CVE-2018-17693",
                "CVE-2018-17700", "CVE-2018-17701");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-12 13:41:54 +0530 (Mon, 12 Nov 2018)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities-Nov18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists,

  - within the conversion of HTML files to PDF. The issue results from the lack
    of validating the existence of an object prior to performing operations
    on the object.

  - The specific flaw exists within the handling of Array.prototype.concat.
    The issue results from the lack of proper validation of user-supplied data,
    which can result in a read past the end of an allocated object.

  - The specific flaw exists within fxhtml2pdf. The issue results from the
    lack of proper validation of user-supplied data, which can result in a
    memory access past the end of an allocated buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code or cause a denial of service
  (use-after-free)");

  script_tag(name:"affected", value:"Foxit PhantomPDF version before 8.3.8 on windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 8.3.8
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

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

if(version_is_less(version:pdfVer, test_version:"8.3.8"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"8.3.8", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
