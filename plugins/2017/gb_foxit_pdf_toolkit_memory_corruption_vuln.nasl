###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_pdf_toolkit_memory_corruption_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Foxit PDF Toolkit PDF File Parsing Memory Corruption Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:foxit_pdf_toolkit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810521");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-5364");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-25 15:52:27 +0530 (Wed, 25 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Foxit PDF Toolkit PDF File Parsing Memory Corruption Vulnerability");

  script_tag(name:"summary", value:"The host is installed with
  Foxit PDF Toolkit and is prone to memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption
  vulnerability in Foxit PDF Toolkit while parsing PDF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  allow an attacker to cause denial of Service and remote code execution
  when the victim opens the specially crafted PDF file.");

  script_tag(name:"affected", value:"Foxit PDF Toolkit version 1.3");

  script_tag(name:"solution", value:"Upgrade to Foxit PDF Toolkit version
  2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_pdf_toolkit_detect.nasl");
  script_mandatory_keys("foxit/pdf_toolkit/win/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!fpdftVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:fpdftVer, test_version:"1.3"))
{
  report = report_fixed_ver(installed_version:fpdftVer, fixed_version: "2.0");
  security_message(data:report );
  exit(0);
}

exit(0);
