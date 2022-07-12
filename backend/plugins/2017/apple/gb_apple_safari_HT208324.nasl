###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Security Updates( HT208324 )
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812284");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-7156", "CVE-2017-7157", "CVE-2017-7160", "CVE-2017-13856",
                "CVE-2017-13866", "CVE-2017-13870", "CVE-2017-5753", "CVE-2017-5715",
                "CVE-2017-7161", "CVE-2017-13885", "CVE-2017-7165", "CVE-2017-13884",
                "CVE-2017-7153");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-12-28 14:26:04 +0530 (Thu, 28 Dec 2017)");
  script_name("Apple Safari Security Updates( HT208324 )");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple
  memory corruption issues, command injection issue in Web Inspector, redirect
  responses to '401 Unauthorized' and other multiple errors leading to 'speculative
  execution side-channel attacks' that affect many modern processors and
  operating systems including Intel, AMD, and ARM.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code or
  cause a denial of service or gain access to potentially sensitive information
  or spoof user interface.");

  script_tag(name:"affected", value:"Apple Safari versions before 11.0.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 11.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208324");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208403");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
path = infos['location'];


if(version_is_less(version:safVer, test_version:"11.0.2"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"11.0.2", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
