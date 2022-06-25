###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2018-01_2018-01_win.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Mozilla Firefox Security Updates(mfsa_2018-01_2018-01)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812295");
  script_version("$Revision: 12068 $");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 14:36:19 +0530 (Fri, 05 Jan 2018)");
  script_name("Mozilla Firefox Security Updates(mfsa_2018-01_2018-01)-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to
  multiple errors leading to 'speculative execution side-channel attacks'
  that affect many modern processors, operating systems and browser
  JavaScript engines.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow code on a malicious web page to read data from
  other web sites (violating the same-origin policy) or private data from the
  browser itself.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 57.0.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 57.0.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-01/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"57.0.4"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0.4", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
