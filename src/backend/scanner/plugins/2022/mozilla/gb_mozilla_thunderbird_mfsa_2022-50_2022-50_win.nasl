# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826721");
  script_version("2022-12-01T10:11:22+0000");
  script_cve_id("CVE-2022-45414");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-01 12:51:38 +0530 (Thu, 01 Dec 2022)");
  script_name("Mozilla Thunderbird Security Update(mfsa_2022-50_2022-50)-Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to a security
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when a Thunderbird user quoted
  from an HTML email and the email contained either a VIDEO tag with the POSTER
  attribute or an OBJECT tag with a DATA attribute, a network request to the
  referenced remote URL was performed, regardless of a configuration to block
  remote content.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute JavaScript code included in the message in the context
  of the message compose document, read and modify the contents of the message
  compose document, including the quoted original message, which could potentially
  contain the decrypted plaintext of encrypted data in the crafted email.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  102.5.1 or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-50/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.5.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.5.1", install_path:path);
  security_message(data:report);
  exit(0);
}
