###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_7zip_win_rar_dos_vuln.nasl 10231 2018-06-18 03:58:33Z ckuersteiner $
#
# 7zip RAR Denial of Service Vulnerability (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107312");
  script_version("$Revision: 10231 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 05:58:33 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-11 16:37:09 +0200 (Fri, 11 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-10115");
  script_name("7zip RAR Denial of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"summary", value:"7zip is prone to a RAR Denial of Service Vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Incorrect initialization logic of RAR decoder objects in 7-Zip 18.03 and before
  can lead to usage of uninitialized memory, allowing remote attackers to cause a denial of service (segmentation fault)
  or execute arbitrary code via a crafted RAR archive.");
  script_tag(name:"affected", value:"7zip through version 18.03.");
  script_tag(name:"solution", value:"Upgrade to 7zip version 18.05 or later.");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sevenzip/discussion/45797/thread/e730c709/?limit=25&page=1#b240");
  exit(0);
}

CPE = "cpe:/a:7-zip:7-zip";

include ("host_details.inc");
include ("version_func.inc");

if (!infos = get_app_version_and_location (cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}
vers = infos ['version'];
path = infos ['location'];

if (version_is_less (version:vers, test_version:"18.05")){
  report = report_fixed_ver (installed_version:vers, fixed_version:"18.05", install_path:path);
  security_message (port:0, data:report);
  exit (0);
}

exit (99);
