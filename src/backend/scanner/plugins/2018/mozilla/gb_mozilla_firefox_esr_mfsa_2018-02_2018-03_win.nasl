###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mfsa_2018-02_2018-03_win.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Mozilla Firefox ESR Security Updates(mfsa_2018-02_2018-03)-Windows
#
# Authors:
# Shakeel <bshakeeel@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812670");
  script_version("$Revision: 12068 $");
  script_cve_id("CVE-2018-5091", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097",
                "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103",
                "CVE-2018-5104", "CVE-2018-5117", "CVE-2018-5089");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 13:02:28 +0530 (Wed, 24 Jan 2018)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2018-02_2018-03)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple use-after-free vulnerabilities and integer overflow errors.

  - URL spoofing with right-to-left text aligned left-to-right.

  - Memory safety bugs");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code on
  affected system or conduct a denial-of-service condition and conduct spoofing
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  52.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 52.6
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-03/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"52.6"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.6", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
