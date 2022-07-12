###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_livesafe_mitm_vuln.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# McAfee LiveSafe Man-in-the-Middle Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:mcafee:livesafe";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112047");
  script_version("$Revision: 11901 $");
  script_cve_id("CVE-2017-3898");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-18 08:36:57 +0200 (Mon, 18 Sep 2017)");
  script_name("McAfee LiveSafe Man-in-the-Middle Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee LiveSafe
  and is prone to a man-in-the-middle vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A man-in-the-middle attack vulnerability in the non-certificate-based authentication mechanism
  allows network attackers to modify the Windows registry value associated with the McAfee update via the HTTP backend-response.");

  script_tag(name:"affected", value:"McAfee LiveSafe 16.0.2 and lower");

  script_tag(name:"solution", value:"Update to version 16.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://service.mcafee.com/FAQDocument.aspx?lc=1033&id=TS102723");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_livesafe_detect.nasl");
  script_mandatory_keys("McAfee/LiveSafe/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com/us/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!ver = get_app_version(cpe:CPE)){
  exit(0);
}

if (res = eregmatch(pattern:"^[0-9]+.[0-9]+", string:ver))
{
  ver = res[0];
}

if (version_is_less_equal(version:ver, test_version:"16.0.2"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"16.0.3");
  security_message(data:report);
  exit(0);
}

