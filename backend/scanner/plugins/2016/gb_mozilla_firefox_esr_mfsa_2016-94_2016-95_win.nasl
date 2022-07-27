###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mfsa_2016-94_2016-95_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Mozilla Firefox ESR Security Updates(mfsa_2016-94_2016-95)-Windows
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809838");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-9899", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898",
		"CVE-2016-9900", "CVE-2016-9904", "CVE-2016-9905", "CVE-2016-9901",
		"CVE-2016-9902", "CVE-2016-9893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 15:13:43 +0530 (Thu, 15 Dec 2016)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2016-94_2016-95)-Windows");

  script_tag(name:"summary", value:"This host is installed with  Mozilla
  Firefox Esr and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - An use-after-free error while manipulating DOM events and audio elements.

  - A CSP bypass using marquee tag.

  - A memory corruption in libGLES.

  - An use-after-free error in Editor while manipulating DOM subtrees.

  - A restricted external resources can be loaded by SVG images through data URLs.

  - A cross-origin information leak in shared atoms.

  - An error while adding or removing sub-documents.

  - A data from Pocket server improperly sanitized before execution.

  - A pocket extension does not validate the origin of events.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause denial of service, to leak
  sensitive information and also could run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  45.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR 45.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-95");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_less(version:ffVer, test_version:"45.6"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.6");
  security_message(data:report);
  exit(0);
}
