# OpenVAS Vulnerability Test
# $Id: libpng_CB-A08-0064.nasl 12727 2018-12-10 07:22:33Z cfischer $
# Description: libpng vulnerability
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
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
#

CPE = "cpe:/a:libpng:libpng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90021");
  script_version("$Revision: 12727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 08:22:33 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-03 22:30:27 +0200 (Wed, 03 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1382");
  script_name("libpng 'CVE-2008-1382' Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_libpng_detect_lin.nasl");
  script_mandatory_keys("Libpng/Version");

  script_tag(name:"solution", value:"All users should upgrade to the latest libpng version of their Linux Distribution.");

  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-1382.");

  script_tag(name:"impact", value:"libpng 1.0.6 through 1.0.32, 1.2.0 through 1.2.26,
  and 1.4.0beta01 through 1.4.0beta19 allows context-dependent attackers to cause a
  denial of service (crash) and possibly execute arbitrary code via a PNG file with
  zero length unknown chunks, which trigger an access of uninitialized memory.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"1.0.6", test_version2:"1.0.32" ) ||
    version_in_range( version:vers, test_version:"1.2.0", test_version2:"1.2.26" ) ||
    version_in_range( version:vers, test_version:"1.4.0beta01", test_version2:"1.4.0beta19" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
}

exit( 0 );