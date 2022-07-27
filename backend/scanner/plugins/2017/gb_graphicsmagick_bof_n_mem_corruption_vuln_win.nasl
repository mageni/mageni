###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_bof_n_mem_corruption_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# GraphicsMagick Memory Corruption And Buffer Overflow Vulnerabilities (Windows)
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

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810561");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684", "CVE-2016-9830");
  script_bugtraq_id(93779, 93600, 93597, 94625);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-21 10:39:33 +0530 (Tue, 21 Feb 2017)");
  script_name("GraphicsMagick Memory Corruption And Buffer Overflow Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with GraphicsMagick
  and is prone to multiple buffer overflow and memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - A stack-based buffer overflow error in 'ReadSCTImage' function in
    coders/sct.c script.

  - A memory corruption error in 'ReadPCXImage' function in
    coders/pcx.c script.

  - A memory corruption error in 'MagickMalloc' function in
    magick/memory.c script.

  - A memory allocation failure in 'MagickRealloc' function in 'memory.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service and to have some unspecified impacts.");

  script_tag(name:"affected", value:"GraphicsMagick version 1.3.25
  on Windows");

  script_tag(name:"solution", value:"Upgrade to GraphicsMagick version 1.3.26
  (not yet released).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/09/15/graphicsmagick-stack-based-buffer-overflow-in-readsctimage-sct-c");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/09/15/graphicsmagick-memory-allocation-failure-in-readpcximage-pcx-c");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/09/15/graphicsmagick-memory-allocation-failure-in-magickmalloc-memory-c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1385583");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2016-9830");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  script_xref(name:"URL", value:"http://www.graphicsmagick.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(gmVer == "1.3.25")
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.26");
  security_message(data:report);
  exit(0);
}
