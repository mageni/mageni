# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814963");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-7098", "CVE-2019-7099", "CVE-2019-7100", "CVE-2019-7101",
                "CVE-2019-7102", "CVE-2019-7103", "CVE-2019-7104");
  script_bugtraq_id(107822);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 13:38:50 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Shockwave Player Multiple Unspecified Memory Corruption Vulnerabilities(APSB19-20)");

  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave
  Player and is prone to multiple unspecified memory corruption vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists in Adobe Shockwave
  Player, which could allow for arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application. Failed exploit attempts will likely result in
  denial-of-service conditions");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before 12.3.5.205 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 12.3.5.205
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb19-20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

vers = infos['version'];
path = infos['location'];
if(version_is_less(version:vers, test_version:"12.3.5.205"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"12.3.5.205", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
