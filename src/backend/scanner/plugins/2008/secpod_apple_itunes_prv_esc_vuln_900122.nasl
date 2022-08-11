##############################################################################
# OpenVAS Vulnerability Test
# Description: Apple iTunes Local Privilege Escalation Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900122");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_bugtraq_id(31089);
  script_cve_id("CVE-2008-3636");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("Apple iTunes Local Privilege Escalation Vulnerability");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020839.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2008/Sep/msg00001.html");

  script_tag(name:"summary", value:"The host is installed with Apple iTunes, which prone to privilege
  escalation vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to integer overflow error in a third-party
  driver bundled with iTune.");

  script_tag(name:"affected", value:"Apple iTunes versions prior to 8.0 on Windows");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 8.0 or later.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to obtain elevated
  privileges thus compromising the affected system.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( egrep( pattern:"^([0-6]\..*|7\.[0-9](\..*)?)$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );