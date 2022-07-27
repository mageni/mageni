###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_72711.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Samba 'TALLOC_FREE()' Function Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105231");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-04 10:23:51 +0100 (Wed, 04 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(72711);
  script_cve_id("CVE-2015-0240");
  script_name("Samba 'TALLOC_FREE()' Function Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72711");
  script_xref(name:"URL", value:"http://www.samba.org");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with root
  privileges. Failed exploit attempts will cause a denial-of-service condition");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Netlogon server implementation in smbd performs a free operation on an
  uninitialized stack pointer, which allows remote attackers to execute arbitrary code via crafted Netlogon packets
  that use the ServerPasswordSet RPC API, as demonstrated by packets reaching the _netr_ServerPasswordSet function
  in rpc_server/netlogon/srv_netlog_nt.c.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");
  script_tag(name:"summary", value:"Samba 'TALLOC_FREE()' Function Remote Code Execution Vulnerability");

  script_tag(name:"affected", value:"Samba 3.5.x and 3.6.x before 3.6.25,
  4.0.x before 4.0.25,
  4.1.x before 4.1.17,
  and 4.2.x before 4.2.0rc5");

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

if( version_is_less( version:vers, test_version:"3.6.25" ) ||
    version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.24" ) ||
    version_in_range( version:vers, test_version:"4.1", test_version2:"4.1.16" ) ||
    version_in_range( version:vers, test_version:"4.2", test_version2:"4.2.0rc4" )
   ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.25 or 4.0.25 or 4.1.17, 4.2.0rc5, or later", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
