##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_virtualbox_acquiredaemonlock_vuln_lin_900408.nasl 12728 2018-12-10 07:40:26Z cfischer $
# Description: Sun xVM VirtualBox Insecure Temporary Files Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:sun:xvm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900408");
  script_version("$Revision: 12728 $");
  script_bugtraq_id(32444);
  script_cve_id("CVE-2008-5256");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 08:40:26 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Sun xVM VirtualBox Insecure Temporary Files Vulnerability (Linux)");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  script_xref(name:"URL", value:"http://secunia.com/Advisories/32851");
  script_xref(name:"URL", value:"http://www.virtualbox.org/wiki/Changelog");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker perform malicious actions
  with the escalated previleges.");

  script_tag(name:"affected", value:"Sun xVM VirutalBox version prior to 2.0.6 versions on all Linux platforms.");

  script_tag(name:"insight", value:"Error is due to insecured handling of temporary files in the 'AcquireDaemonLock'
  function in ipcdUnix.cpp. This allows local users to overwrite arbitrary
  files via a symlink attack on a '/tmp/.vbox-$USER-ipc/lock' temporary file.");

  script_tag(name:"solution", value:"Upgrade to the latest version 2.0.6 or later.");

  script_tag(name:"summary", value:"This host is installed with Sun xVM VirtualBox and is prone to
  Insecure Temporary Files vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"2.0.6" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.6", install_path:path );
  security_message( port:0, data:report );
}

exit( 0 );