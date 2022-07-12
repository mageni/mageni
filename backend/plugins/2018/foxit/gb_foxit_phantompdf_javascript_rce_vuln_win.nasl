###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit PhantomPDF 'JavaScript' Remote Code Execution Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813264");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-14295", "CVE-2018-17706", "CVE-2018-17624", "CVE-2018-17622",
                "CVE-2018-17620", "CVE-2018-17621", "CVE-2018-17618", "CVE-2018-17619",
                "CVE-2018-17617", "CVE-2018-17615", "CVE-2018-17616");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-20 15:00:12 +0530 (Fri, 20 Jul 2018)");
  script_name("Foxit PhantomPDF 'JavaScript' Remote Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The user-after-free vulnerability that exists in the JavaScript, When
    executing embedded JavaScript code a document can be cloned. which frees
    a lot of used objects, but the JavaScript can continue to execute.

  - The use-after-free vulnerability found in the Javascript engine that can
    result in remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit PhantomPDF versions before 9.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 9.2
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

if(version_is_less(version:pdfVer, test_version:"9.2"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.2", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
