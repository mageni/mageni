###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_smbxcli_base_mima_vuln.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Samba 'libcli/smb/smbXcli_base.c' Man In The Middle (MIMA) Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807345");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-2119");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-12 12:51:22 +0530 (Tue, 12 Jul 2016)");
  script_name("Samba 'libcli/smb/smbXcli_base.c' Man In The Middle (MIMA) Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2119.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-2119");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to man-in-the-middle vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the way DCE/RPC
  connections are initiated by the user. Any authenticated DCE/RPC connection
  that a client initiates against the server could be use by a man-in-the middle
  attacker to impersonate the server by injecting the SMB2_SESSION_FLAG_IS_GUEST
  or SMB2_SESSION_FLAG_IS_NULL flag.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass a client-signing protection mechanism, and consequently
  spoof SMB2 and SMB3 servers.");

  script_tag(name:"affected", value:"Samba versions 4.x before 4.2.14,
  4.3.x before 4.3.11, and 4.4.x before 4.4.5.");

  script_tag(name:"solution", value:"Upgrade to Samba version 4.2.14
  or 4.3.11 or 4.4.5 or later.");

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

if( version_in_range( version:vers, test_version:"4.0.0", test_version2:"4.2.13" ) ) {
  fix = "4.2.14";
  VULN = TRUE ;
} else if( version_in_range( version:vers, test_version:"4.3.0", test_version2:"4.3.10" ) ) {
  fix = "4.3.11";
  VULN = TRUE ;
} else if( version_in_range( version:vers, test_version:"4.4.0", test_version2:"4.4.4" ) ) {
  fix = "4.4.5";
  VULN = TRUE ;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );