###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mult_vuln_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox ESR Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806101");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-31 16:24:54 +0530 (Mon, 31 Aug 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free vulnerability with a '<canvas>' element on a page. This
  occurs when a resize event is triggered in concert with style changes but
  the canvas references have been recreated in the meantime, destroying the
  originally referenced context. This results in an exploitable crash.

  - A vulnerablity in the way Firefox handles installation of add-ons.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code by leveraging improper interaction between
  resize events and changes to Cascading Style Sheets (CSS) token sequences for
  a CANVAS element and to bypass an intended user-confirmation requirement by
  constructing a crafted data.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 38.x before 38.2.1 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 38.2.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-94");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_in_range(version:ffVer, test_version:"38.0.0", test_version2:"38.2.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.2.1" + '\n';
  security_message(data:report);
  exit(0);
}
