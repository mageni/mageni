##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_pro_antivirus_multiple_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Avast Pro Antivirus Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:avast:avast_pro_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811021");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-8308", "CVE-2017-8307");
  script_bugtraq_id(98084, 98086);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-05 13:59:15 +0530 (Fri, 05 May 2017)");
  script_name("Avast Pro Antivirus Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Avast Pro
  Antivirus and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to design errors in
  the application. Using LPC interface API exposed by the AvastSVC.exe Windows
  service it is possible to delete arbitrary file, replace arbitrary file and
  launch predefined binaries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct a denial-of-service condition, execute arbitrary code and bypass
  certain security features on the affected system.");

  script_tag(name:"affected", value:"Avast Pro Antivirus version prior to
  version 17.0");

  script_tag(name:"solution", value:"Upgrade to Avast Pro Antivirus version
  17.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/Multiple-Vulnerabilities-in-Avast-Antivirus/?fid=9201");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_pro_detect.nasl");
  script_mandatory_keys("Avast/Pro_Antivirus/Win/Ver");
  script_xref(name:"URL", value:"https://www.avast.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:avastVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"17.0");
  security_message(data:report);
  exit(0);
}
