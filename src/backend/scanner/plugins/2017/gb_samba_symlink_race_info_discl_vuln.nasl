###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_symlink_race_info_discl_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Samba Server Symlink Race Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810729");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-2619");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-04 11:09:27 +0530 (Tue, 04 Apr 2017)");
  script_name("Samba Server Symlink Race Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41740/");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1039");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-2619.html");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The time-of-check, time-of-use race
  condition in Samba, a SMB/CIFS file, print, and login server for Unix.
  A malicious client can take advantage of this flaw by exploiting a symlink
  race to access areas of the server file system not exported under a share
  definition.");

  script_tag(name:"impact", value:"Successful exploitation will allow clients
  to access non-exported parts of the file system via symlinks.");

  script_tag(name:"affected", value:"Samba Server versions 4.6.x before 4.6.1,

  Samba Server versions 4.4.x before 4.4.12, and

  Samba Server versions 4.5.x before 4.5.7.");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.1 or 4.4.12 or 4.5.7 or later.");

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

if(version_is_equal( version:vers, test_version:"4.6.0" )){
  fix = "4.6.1";
  VULN = TRUE ;
}
else if( version_in_range( version:vers, test_version:"4.4.0", test_version2:"4.4.11" )){
  fix = "4.4.11";
  VULN = TRUE ;
}
else if( version_in_range( version:vers, test_version:"4.5.0", test_version2:"4.5.6" )){
  fix = "4.5.7";
  VULN = TRUE ;
}

if( VULN ){
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
