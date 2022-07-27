###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_sol68785753.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# F5 BIG-IP - SOL68785753 - ImageMagick vulnerability CVE-2015-8898
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140080");
  script_cve_id("CVE-2015-8898");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12338 $");

  script_name("F5 BIG-IP - SOL68785753 - ImageMagick vulnerability CVE-2015-8898");

  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/k/68/sol68785753.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"ImageMagick vulnerability CVE-2015-8898");
  script_tag(name:"impact", value:"BIG-IP systems that use a WebAcceleration profile configured with the Image Optimization settings (BIG-IP AAM and BIG-IP WebAccelerator) are vulnerable to this issue. An attacker using specially crafted image format files could cause memory corruption and, potentially, run arbitrary code with restricted user privileges, resulting in a denial- of -service (DoS) attack or an application restart.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-29 09:59:41 +0100 (Tue, 29 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("f5.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

check_f5['WAM'] = make_array( 'affected',   '11.2.1;',
                              'unaffected', '10.2.1-10.2.4;');

if( report = is_f5_vulnerable( ca:check_f5, version:version ) )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

