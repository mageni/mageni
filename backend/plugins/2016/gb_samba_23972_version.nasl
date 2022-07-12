###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_23972_version.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Samba MS-RPC Remote Shell Command Execution Vulnerability (Version Check)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108012");
  script_version("$Revision: 12363 $");
  script_cve_id("CVE-2007-2447");
  script_bugtraq_id(23972);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-31 12:47:00 +0200 (Mon, 31 Oct 2016)");
  script_name("Samba MS-RPC Remote Shell Command Execution Vulnerability (Version Check)");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Gain a shell remotely");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23972");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-2447.html");

  script_tag(name:"summary", value:"Samba is prone to a vulnerability that allows attackers to execute arbitrary shell
  commands because the software fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary shell commands on an affected
  system with the privileges of the application.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced vendor advisory.");

  script_tag(name:"affected", value:"This issue affects Samba 3.0.0 to 3.0.25rc3.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if( version_is_less_equal( version:vers, test_version:"3.0.25rc3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See referenced vendor advisory", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
