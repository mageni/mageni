###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_multiple_products_69461.nasl 11225 2018-09-04 13:06:36Z mmartin $
#
# Multiple F5 Networks Products Remote Code Execution Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105172");
  script_bugtraq_id(69461);
  script_cve_id("CVE-2014-2927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11225 $");
  script_name("Multiple F5 Networks Products Remote Code Execution Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 15:06:36 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-19 11:51:31 +0100 (Mon, 19 Jan 2015)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("rsync_modules.nasl");
  script_require_ports("Services/rsync", 873);
  script_mandatory_keys("rsync/modules_in_kb");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69461");
  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/15000/200/sol15236.html");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code within
  the context of the application.");

  script_tag(name:"vuldetect", value:"Try to read the /VERSION file via a rsync request.");

  script_tag(name:"insight", value:"An open Rsync configuration for the ConfigSync IP address allows for remote
  read/write file system access in BIG-IP 11.x versions before 11.6.0, 11.5.1 HF3, 11.5.0 HF4, 11.4.1 HF4, 11.4.0 HF7,
  11.3.0 HF9, and 11.2.1 HF11, and Enterprise Manager 3.x versions before 3.1.1 HF2.");

  script_tag(name:"solution", value:"Disable the rsync daemon");

  script_tag(name:"summary", value:"Multiple F5 Networks Products are prone to a remote code-execution
  vulnerability.");

  script_tag(name:"affected", value:"F5 BIG-IP 11.6 before 11.6.0,
  11.5.1 before HF3,
  11.5.0 before HF4,
  11.4.1 before HF4,
  11.4.0 before HF7,
  11.3.0 before HF9,
  and 11.2.1 before HF11
  Enterprise Manager 3.x before 3.1.1 HF2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("rsync_func.inc");

port = get_rsync_port( default:873 );

if( ! modules = get_kb_item( 'rsync/' + port + '/modules' ) ) exit( 0 );

if( "csync" >< modules ) {
  module = 'csync';
} else if( "cmi" >< modules ) {
  module = 'cmi';
}

if( ! module ) exit( 0 );

if( ! soc = rsync_connect( port:port ) ) exit( 0 );
buf =  get_file( soc:soc, module:module, file:'VERSION' );
close( soc );

if( "Product: BIG-IQ" >< buf || "Product: BIG-IP" >< buf || "Product: EM" >< buf ) {
  report = 'It was possible to download the VERSION file from the remote host via the ' + module + ' module:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
