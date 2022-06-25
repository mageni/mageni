###############################################################################
# OpenVAS Vulnerability Test
#
# K7 Anti-Virus Premium Multiple Vulnerabilities Sep18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:k7computing:antivirus_premium";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813922");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-17429", "CVE-2017-16557", "CVE-2017-16555", "CVE-2017-16556",
                "CVE-2017-16553", "CVE-2017-16554", "CVE-2017-16551", "CVE-2017-16552",
                "CVE-2017-16550", "CVE-2017-16549");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-03 15:24:05 +0530 (Mon, 03 Sep 2018)");
  script_name("K7 Anti-Virus Premium Multiple Vulnerabilities Sep18");

  script_tag(name:"summary", value:"The host is installed with K7 Antivirus
  Premium is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - User-controlled input to the K7Sentry device not being sufficiently
    authenticated.

  - Improper sanitization against input-output control system calls.

  - Improper sanitization against user-controlled input.");

  script_tag(name:"impact", value:"Successful exploitation would allow attackers
  to access a raw hard disk, write to arbitrary memory locations and gain
  privileges.");

  script_tag(name:"affected", value:"K7 Anti-Virus Premium before 15.1.0.53");

  script_tag(name:"solution", value:"K7 Anti-Virus Premium version 15.1.0.53. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  #Only major version can be detected
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"https://support.k7computing.com/index.php?/Knowledgebase/Article/View/173/41/advisory-issued-on-6th-november-2017");
  script_xref(name:"URL", value:"https://www.k7computing.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_k7_anti_virus_premium_detect_win.nasl");
  script_mandatory_keys("K7/AntiVirusPremium/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
kVer = infos['version'];
kPath = infos['location'];

if(version_is_less_equal(version:kVer, test_version:"15.00"))
{
  report = report_fixed_ver(installed_version:kVer, fixed_version:"15.1.0.53", install_path:kPath);
  security_message(data:report);
  exit(0);
}
