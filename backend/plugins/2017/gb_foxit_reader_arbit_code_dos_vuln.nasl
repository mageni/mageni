###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_arbit_code_dos_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Foxit Reader Arbitrary Code Execution and Denial of Service Vulnerabilities (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112056");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-14694", "CVE-2017-15770", "CVE-2017-15771");
  script_bugtraq_id(101009, 101540, 101549);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-26 11:18:43 +0530 (Thu, 26 Oct 2017)");
  script_name("Foxit Reader Arbitrary Code Execution and Denial of Service Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to a code execution and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Foxit Reader allows attackers to execute arbitrary code or
      cause a denial of service via a crafted .pdf file, related to 'Data from Faulting Address controls Code Flow starting at
      tiptsf!CPenInputPanel::FinalRelease+0x000000000000002f'.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code or crash the application via a buffer
  overflow.");

  script_tag(name:"affected", value:"Foxit Reader version 8.3.2.25013 and earlier on Windows");
  script_tag(name:"solution", value:"Update to Foxit Reader 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-14694");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-15771");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-15770");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"8.3.2.25013"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"9.0");
  security_message(data:report);
  exit(0);
}
