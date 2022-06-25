###############################################################################
# OpenVAS Vulnerability Test
#
# McAfee True Key DLL Side Loading Privilege Elevation Vulnerability (Windows)
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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

CPE = "cpe:/a:mcafee:true_key";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813323");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6661");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-02 16:31:27 +0530 (Wed, 02 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("McAfee True Key DLL Side Loading Privilege Elevation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running McAfee True Key and is
  prone to privilege elevation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to one of the True Key Service
  binaries loading a McAfee dynamic library in an insecure manner. An adversary could
  carefully craft an exploit to launch an Elevation of Privilege attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privilege elevation via not verifying a particular DLL file
  signature.");

  script_tag(name:"affected", value:"True Key version 4.20 and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 4.20.110 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102801");
  script_xref(name:"URL", value:"https://service.mcafee.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_true_key_detect_win.nasl");
  script_mandatory_keys("McAfee/TrueKey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
tVer = infos['version'];
tPath = infos['location'];

if(version_is_less_equal(version:tVer, test_version:"4.20"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"4.20.110", install_path:tPath);
  security_message(data:report);
  exit(0);
}
exit(0);
