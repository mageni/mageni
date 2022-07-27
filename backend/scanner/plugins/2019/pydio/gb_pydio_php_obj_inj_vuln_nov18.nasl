###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pydio_php_obj_inj_vuln_nov18.nasl 13099 2019-01-16 13:15:35Z jschulte $
#
# Pydio <= 8.2.1 PHO Object Injection Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113325");
  script_version("$Revision: 13099 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-16 14:15:35 +0100 (Wed, 16 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-16 13:45:55 +0200 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20718");

  script_name("Pydio <= 8.2.1 PHO Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"Pydio is prone to a PHP Object Injection Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists due to pydio interpreting any string that
  starts with $phpserial$ as serialized and then procedding to deserialize it.
  During this, an attacker could inject POP gadget chains and eventually make
  a call to call_user_func().");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary commands
  on the target machine.");
  script_tag(name:"affected", value:"Pydio through version 8.2.1.");
  script_tag(name:"solution", value:"Update to version 8.2.2.");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/pydio-unauthenticated-remote-code-execution/");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "8.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );