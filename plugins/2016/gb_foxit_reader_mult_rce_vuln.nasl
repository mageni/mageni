###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_mult_rce_vuln.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Foxit Reader Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807556");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2016-4059", "CVE-2016-4060", "CVE-2016-4061", "CVE-2016-4062",
                "CVE-2016-4063", "CVE-2016-4064", "CVE-2016-4065");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-25 16:44:43 +0530 (Mon, 25 Apr 2016)");
  script_name("Foxit Reader Multiple Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - The multiple Use-after-free vulnerabilities.

  - The error in parsing malformed content stream.

  - The application recursively called the format error of some PDFs and led to
    no response when opening the PDF.

  - The destructor of the object whose generation number is -1 in the PDF file
    could release the file handle which had been imported by the application
    layer.

  - The error in decoding corrupted images during PDF conversion with the gflags
    app enabled.

  - The XFA's underlying data failed to synchronize with that of
    PhantomPDF/Reader caused by the re-layout underlying XFA.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"Foxit Reader version 7.3.0.118 and
  earlier.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  7.3.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-219");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-221");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

## Foxit Reader version 7.3.4 = 7.3.4.311
if(version_is_less_equal(version:foxitVer, test_version:"7.3.0.118"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"7.3.4.311");
  security_message(data:report);
  exit(0);
}
