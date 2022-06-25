###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_arbit_code_exe_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Foxit PhantomPDF Arbitrary Code Execution Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806904");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-8580");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-31 18:45:52 +0530 (Thu, 31 Dec 2015)");
  script_name("Foxit PhantomPDF Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to Arbitrary Code Execution Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within the handling of the
  Print method and App object. A specially crafted PDF document can force a
  dangling pointer to be reused after it has been freed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted PDF document.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version prior to
  7.2.2.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version
  7.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#FRD-34");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_is_less(version:foxitVer, test_version:"7.2.2"))
{
  report = 'Installed version: ' + foxitVer + '\n' +
           'Fixed version:     7.2.2'  + '\n';
  security_message(data:report);
  exit(0);
}
