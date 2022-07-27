###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_sambacry_remote_code_exec_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Samba Remote Code Execution Vulnerability (SambaCry)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811055");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2017-7494");
  script_bugtraq_id(98636);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-25 10:55:47 +0530 (Thu, 25 May 2017)");
  script_name("Samba Remote Code Execution Vulnerability (SambaCry)");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation error,
  which allows a malicious client to upload a shared library to a writable share.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to execute arbitrary code as root on an affected system.");

  script_tag(name:"affected", value:"All Samba Server versions 3.5.0 onwards,

  Samba Server versions 4.4.x before 4.4.14,

  Samba Server versions 4.5.x before 4.5.10, and

  Samba Server versions 4.6.x before 4.6.4");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.4 or 4.5.10 or 4.4.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-7494.html");

  script_xref(name:"URL", value:"http://hackaday.com/2017/05/25/linux-sambacry/");
  script_xref(name:"URL", value:"http://thehackernews.com/2017/05/samba-rce-exploit.html");
  script_xref(name:"URL", value:"https://github.com/omri9741/cve-2017-7494");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if(version_in_range(version:vers, test_version:"3.5.0", test_version2:"4.4.13")){
  fix = "4.4.14";
}

else if(vers =~ "^4\."){
  if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.9")){
    fix = "4.5.10";
  }
  else if(version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.3")){
    fix = "4.6.4";
  }
}

if(fix){
  report = report_fixed_ver( installed_version:vers, fixed_version:fix + " or apply patch", install_path:loc );
  security_message( data:report, port:port);
  exit(0);
}

exit(99);
