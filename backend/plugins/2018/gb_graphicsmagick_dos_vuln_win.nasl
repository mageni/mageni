###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_dos_vuln_win.nasl 9023 2018-03-05 07:08:45Z cfischer $
#
# GraphicsMagick Denial of Service Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112212");
  script_version("$Revision: 9023 $");
  script_cve_id("CVE-2018-6799");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-03-05 08:08:45 +0100 (Mon, 05 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-09 11:31:13 +0100 (Fri, 09 Feb 2018)");
  script_name("GraphicsMagick Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with GraphicsMagick
  and is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks the version.");

  script_tag(name:"insight", value:"The AcquireCacheNexus function in magick/pixel_cache.c allows remote attackers
to cause a denial of service (heap overwrite) or possibly have unspecified other impact via a crafted image file, because a pixel staging area is not used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly have unspecified other impact.

  Impact Level: Application");

  script_tag(name:"affected", value:"GraphicsMagick before version 1.3.28.");

  script_tag(name:"solution", value: "Update to version 1.3.28 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://hg.graphicsmagick.org/hg/GraphicsMagick/rev/b41e2efce6d3");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.3.28")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.28", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);