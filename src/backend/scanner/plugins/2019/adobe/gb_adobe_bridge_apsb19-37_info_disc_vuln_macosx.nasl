# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815246");
  script_version("2019-07-12T06:29:03+0000");
  script_cve_id("CVE-2019-7963");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-12 06:29:03 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-12 10:27:24 +0530 (Fri, 12 Jul 2019)");
  script_name("Adobe Bridge CC Security Updates (apsb19-37)-Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Adobe Bridge CC
  and is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Adobe Bridge CC version 9.0.2 and before on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Bridge CC 9.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://creative.adobe.com/products/download/bridge");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb19-37.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Bridge/CC/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## 9.1 == 9.1.0.338
if(version_is_less(version:vers, test_version:"9.1.0.338"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"9.1 (9.1.0.338)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
