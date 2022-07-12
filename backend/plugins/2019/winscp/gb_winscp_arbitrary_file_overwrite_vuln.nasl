###############################################################################
# OpenVAS Vulnerability Test
#
# WinSCP Arbitrary File Overwrite Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:winscp:winscp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814733");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-20684");
  script_bugtraq_id(106526);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-17 15:17:22 +0530 (Thu, 17 Jan 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinSCP Arbitrary File Overwrite Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with WinSCP and is
  prone to arbitrary file overwrie vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to missing validation in the
  scp implementation where client would accept arbitrary files sent by the server,
  potentially overwriting unrelated files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  servers to overwrite arbitrary files on affected system");

  script_tag(name:"affected", value:"WinSCP before version 5.14 beta on Windows");

  script_tag(name:"solution", value:"Update to WinSCP version 5.14 beta or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt");
  script_xref(name:"URL", value:"https://winscp.net/tracker/1675");
  script_xref(name:"URL", value:"https://github.com/winscp/winscp/commit/49d876f2c5fc00bcedaa986a7cf6dedd6bf16f54");
  script_xref(name:"URL", value:"https://winscp.net/");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_winscp_detect_win.nasl");
  script_mandatory_keys("WinSCP/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
winVer = infos['version'];
path = infos['location'];

if(version_is_less(version:winVer, test_version:"5.14.beta"))
{
  report = report_fixed_ver(installed_version:winVer, fixed_version:"5.14 beta or later", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
