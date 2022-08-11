###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_createfxpdfcovertor_fun_heap_bof_vuln_win.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# Foxit Reader 'CreateFXPDFConvertor' Function Buffer Overflow Vulnerability (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810906");
  script_version("$Revision: 11936 $");
  script_cve_id("CVE-2016-3740");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 17:41:48 +0530 (Fri, 07 Apr 2017)");
  script_name("Foxit Reader 'CreateFXPDFConvertor' Function Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to heap based buffer overfolw vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to heap-based buffer
  overflow error in the 'CreateFXPDFConvertor' function in
  'ConvertToPdf_x86.dll'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via crafted TIFF image.");

  script_tag(name:"affected", value:"Foxit Reader version 7.3.4.311");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 8.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://0patch.blogspot.in/2016/07/0patching-foxit-readers-heap-buffer.html");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:foxitVer, test_version:"7.3.4.311"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.0");
  security_message(data:report);
  exit(0);
}
