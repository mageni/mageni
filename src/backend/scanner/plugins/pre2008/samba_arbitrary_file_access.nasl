###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_arbitrary_file_access.nasl 10398 2018-07-04 12:11:48Z cfischer $
#
# Samba Remote Arbitrary File Access
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:samba:samba";

#  Ref: Karol Wiesek - iDEFENSE

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15394");
  script_version("$Revision: 10398 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 14:11:48 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(11216, 11281);
  script_cve_id("CVE-2004-0815");
  script_name("Samba Remote Arbitrary File Access");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"insight", value:"An attacker needs a valid account to exploit this flaw.");

  script_tag(name:"solution", value:"Upgrade to Samba 2.2.11 or 3.0.7.");

  script_tag(name:"summary", value:"The remote Samba server, according to its version number, is vulnerable
  to a remote file access vulnerability.");

  script_tag(name:"impact", value:"This vulnerability allows an attacker to access arbitrary files which exist
  outside of the shares's defined path.");

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

if( version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.10" ) ||
    version_in_range( version:vers, test_version:"3.0.0", test_version2:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.11/3.0.7", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
