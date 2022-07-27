###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_nmbd_rce_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Samba 'nmbd' NetBIOS Name Services Daemon Remote Code Execution Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811220");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2014-3560");
  script_bugtraq_id(69021);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-22 12:47:01 +0530 (Thu, 22 Jun 2017)");
  script_name("Samba 'nmbd' NetBIOS Name Services Daemon Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030663");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2014-3560");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  mechanism to avoid buffer overwriting. A malicious user can send packets
  that may overwrite the heap of the target nmbd NetBIOS name services daemon.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Samba Server versions 4.0.x before 4.0.21
  and 4.1.x before 4.1.11.");

  script_tag(name:"solution", value:"Upgrade to Samba 4.0.21 or 4.1.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.samba.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if(vers =~ "^4\.[01]"){
  if(version_is_less(version:vers, test_version:"4.0.21")){
    fix = "4.0.21";
  }
  else if(version_in_range(version:vers, test_version:"4.1", test_version2:"4.1.10")){
    fix = "4.1.11";
  }
}

if(fix){
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port);
  exit(0);
}

exit(99);
