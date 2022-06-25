##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Update(stable-channel-update-for-desktop_19-2018-11)-MAC OS X
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814501");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1747");
  script_bugtraq_id(105946);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-20 10:44:42 +0530 (Tue, 20 Nov 2018)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_19-2018-11)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due the use after free
  error in GPU.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Google Chrome version prior to 70.0.3538.110 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 70.0.3538.110 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/11/stable-channel-update-for-desktop_19.html");
  script_xref(name:"URL", value:"https://www.google.com/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"70.0.3538.110"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"70.0.3538.110", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
