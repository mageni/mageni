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

CPE = "cpe:/a:tortoisesvn:tortoisesvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107701");
  script_version("2019-08-30T09:47:09+0000");
  script_cve_id("CVE-2019-14422");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-30 09:47:09 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-28 17:43:37 +0200 (Wed, 28 Aug 2019)");
  script_name("TortoiseSVN <= 1.12.1 Remote Code Execution (RCE) Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tortoise_svn_detect.nasl");
  script_mandatory_keys("tortoisesvn/detected");

  script_xref(name:"URL", value:"https://tortoisesvn.net/Changelog.txt");
  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2188");

  script_tag(name:"summary", value:"This host is installed with TortoiseSVN and is prone to a remote
  code-execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code to compromise the target system.");

  script_tag(name:"affected", value:"TortoiseSVN through version 1.12.1.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - The URI handler of TortoiseSVN (Tsvncmd:) allows a customised diff operation on Excel workbooks,
    which could be used to open remote workbooks without protection from macro security settings.

  - The `tsvncmd:command:diff?path:[file1]?path2:[file2]` will execute a customised diff on [file1]
    and [file2] based on the file extension. For xls files, it will execute the script `diff-xls.js`
    using wscript, which will open the two files for analysis without any macro security warning.");

  script_tag(name:"solution", value:"Update to TortoiseSVN version 1.12.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"1.12.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.12.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
