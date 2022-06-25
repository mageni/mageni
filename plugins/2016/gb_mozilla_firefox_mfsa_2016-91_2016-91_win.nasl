###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2016-91_2016-91_win.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Mozilla Firefox Security Updates( mfsa_2016-91_2016-91 )-Windows
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809823");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2016-9078");
  script_bugtraq_id(94569);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 12:04:46 +0530 (Thu, 01 Dec 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-91_2016-91 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to URL redirection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists as data: URL can inherit
  wrong origin after an HTTP redirect.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to redirect a URL maliciously, current data suggests
  it does not have any capacity to impact the host system.");

  script_tag(name:"affected", value:"Mozilla Firefox versions 49.0 and 50.0
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 50.0.1
  or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-91");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"49.0", test_version2:"50.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"50.0.1");
  security_message(data:report);
  exit(0);
}
