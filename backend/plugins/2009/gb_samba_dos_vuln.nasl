###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Samba winbind Daemon Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800711");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Samba winbind Daemon Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0308");
  script_xref(name:"URL", value:"http://www.samba.org/samba/history/samba-3.0.32.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/497941/100/0/threaded");

  script_tag(name:"affected", value:"Samba version prior to 3.0.32.");

  script_tag(name:"insight", value:"This flaw is due to a race condition in the winbind daemon which allows
  remote attackers to cause denial of service through unspecified vectors related to an unresponsive child process.");

  script_tag(name:"solution", value:"Upgrade to version 3.0.32 or later.");

  script_tag(name:"summary", value:"This host is installed with Samba for Linux and is prone to
  Winbind daemon Denial of Service Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
loc = infos['location'];

if( version_is_less( version:vers, test_version:"3.0.32" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.32", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );