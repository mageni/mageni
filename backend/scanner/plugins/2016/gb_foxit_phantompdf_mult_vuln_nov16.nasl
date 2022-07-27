###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_mult_vuln_nov16.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Foxit PhantomPDF Multiple Vulnerabilities Nov16
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809304");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-8878", "CVE-2016-8879", "CVE-2016-8877", "CVE-2016-8876",
                "CVE-2016-8875");
  script_bugtraq_id(93608);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-03 14:36:41 +0530 (Thu, 03 Nov 2016)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities Nov16");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The heap buffer overflow and heap corruption vulnerabilities.

  - An Use-After-Free vulnerability.

  - An Out-of-Bounds Read or Out-of-Bounds Write vulnerability.

  - A Null Pointer Deference vulnerability.

  - An Integer Overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to leak sensitive information, execute remote code and also to cause a
  denial of service condition(application crash).");

  script_tag(name:"affected", value:"Foxit PhantomPDF version prior to 8.1.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version
  8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:foxitVer, test_version:"8.1"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.1");
  security_message(data:report);
  exit(0);
}
