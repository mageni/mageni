###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_mult_vuln_aug17_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# GraphicsMagick Multiple Vulnerabilities - Aug17 (Windows)
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

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112027");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-11642", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13066", "CVE-2017-13147", "CVE-2017-13148");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-23 11:38:13 +0200 (Wed, 23 Aug 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities - Aug17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with GraphicsMagick
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick 1.3.26 and prior is prone to multiple vulnerabilities:

  - Allocation failure vulnerabilities.

  - Heap buffer overflow vulnerabilities.

  - Null pointer dereference vulnerabilities.

  - Memory leak vulnerabilities.

  - Invalid memory read vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service via a crafted file.");

  script_tag(name:"affected", value:"GraphicsMagick version 1.3.26 and earlier on Windows");

  script_tag(name:"solution", value:"Updates are available, see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/434/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/436/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/435/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/430/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/446/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-invalid-memory-read-in-setimagecolorcallback-image-c/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-use-after-free-in-readwmfimage-wmf-c/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-heap-based-buffer-overflow-in-readsunimage-sun-c/");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:gmVer, test_version:"1.3.26"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"See Vendor");
  security_message(data:report);
  exit(0);
}
