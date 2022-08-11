##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_invalid_mem_access_dos_vuln_900117.nasl 12728 2018-12-10 07:40:26Z cfischer $
# Description: ClamAV Invalid Memory Access Denial Of Service Vulnerability
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900117");
  script_version("$Revision: 12728 $");
  script_bugtraq_id(30994);
  script_cve_id("CVE-2008-1389");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 08:40:26 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("ClamAV Invalid Memory Access Denial Of Service Vulnerability");
  script_dependencies("gb_clamav_detect_lin.nasl");
  script_mandatory_keys("ClamAV/Lin/Ver");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2484");
  script_xref(name:"URL", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog");

  script_tag(name:"summary", value:"The host is running Clam AntiVirus, which is prone to denial of
  service vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to an invalid memory access in chmunpack.c file,
  when processing a malformed CHM file.");

  script_tag(name:"affected", value:"ClamAV versions prior to ClamAV 0.94 on all platform.");

  script_tag(name:"solution", value:"Upgrade to ClamAV version 0.94.");

  script_tag(name:"impact", value:"Successful remote exploitation will allow attackers to cause
  the application to crash.");

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

if( version_is_less( version:vers, test_version:"0.94" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.94", install_path:path );
  security_message( port:0, data:report );
}

exit( 0 );