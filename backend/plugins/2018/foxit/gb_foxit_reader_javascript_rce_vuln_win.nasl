##############################################################################
# OpenVAS Vulnerability Test
#
# Foxit Reader 'JavaScript' Remote Code Execution Vulnerabilities (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813263");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11617", "CVE-2018-11618", "CVE-2018-11619", "CVE-2018-11620",
                "CVE-2018-11621", "CVE-2018-11622", "CVE-2018-11623", "CVE-2018-14241",
                "CVE-2018-14242", "CVE-2018-14243", "CVE-2018-14244", "CVE-2018-14245",
                "CVE-2018-14246", "CVE-2018-14247", "CVE-2018-14248", "CVE-2018-14249",
                "CVE-2018-14250", "CVE-2018-14251", "CVE-2018-14252", "CVE-2018-14253",
                "CVE-2018-14254", "CVE-2018-14255", "CVE-2018-14256", "CVE-2018-14257",
                "CVE-2018-14258", "CVE-2018-14259", "CVE-2018-14260", "CVE-2018-14261",
                "CVE-2018-14262", "CVE-2018-14263", "CVE-2018-14264", "CVE-2018-14265",
                "CVE-2018-14266", "CVE-2018-14267", "CVE-2018-14268", "CVE-2018-14269",
                "CVE-2018-14270", "CVE-2018-14271", "CVE-2018-14272", "CVE-2018-14273",
                "CVE-2018-14274", "CVE-2018-14275", "CVE-2018-14276", "CVE-2018-14277",
                "CVE-2018-14278", "CVE-2018-14279", "CVE-2018-14280", "CVE-2018-14281",
                "CVE-2018-14282", "CVE-2018-14283", "CVE-2018-14284", "CVE-2018-14285",
                "CVE-2018-14286", "CVE-2018-14287", "CVE-2018-14288", "CVE-2018-14289",
                "CVE-2018-14290", "CVE-2018-14291", "CVE-2018-14292", "CVE-2018-14293",
                "CVE-2018-14294", "CVE-2018-14297", "CVE-2018-14298", "CVE-2018-14299",
                "CVE-2018-14300", "CVE-2018-14301", "CVE-2018-14302", "CVE-2018-14303",
                "CVE-2018-14304", "CVE-2018-14305", "CVE-2018-14306", "CVE-2018-14307",
                "CVE-2018-14308", "CVE-2018-14309", "CVE-2018-14310", "CVE-2018-14311",
                "CVE-2018-14312", "CVE-2018-14313", "CVE-2018-14314", "CVE-2018-14315",
                "CVE-2018-14316", "CVE-2018-14317", "CVE-2018-3924", "CVE-2018-3939",
                "CVE-2018-17624", "CVE-2018-17622", "CVE-2018-17620", "CVE-2018-17621",
                "CVE-2018-17618", "CVE-2018-17619", "CVE-2018-17617", "CVE-2018-17615",
                "CVE-2018-17616");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-20 15:00:12 +0530 (Fri, 20 Jul 2018)");
  script_name("Foxit Reader 'JavaScript' Remote Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader and
  is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The user-after-free vulnerability that exists in the JavaScript, When
    executing embedded JavaScript code a document can be cloned. which frees
    a lot of used objects, but the JavaScript can continue to execute.

  - The use-after-free vulnerability found in the Javascript engine that can
    result in remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit Reader versions before 9.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 9.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");

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

if(version_is_less(version:pdfVer, test_version:"9.2"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.2", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
