###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mfsa_2016-92_2016-92_macosx.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Mozilla Firefox Esr Security Updates( mfsa_2016-92_2016-92 )-MAC OS X
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809827");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2016-9079");
  script_bugtraq_id(94591);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 12:34:34 +0530 (Thu, 01 Dec 2016)");
  script_name("Mozilla Firefox Esr Security Updates( mfsa_2016-92_2016-92 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox Esr and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to,
  Use-after-free in SVG Animation.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service via application crash,
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox Esr version before
  45.5.1 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox Esr version 45.5.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-92");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.5.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.5.1");
  security_message(data:report);
  exit(0);
}
