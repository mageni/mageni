###############################################################################
# OpenVAS Vulnerability Test
#
# Pydio version before 6.0.7 multiple vulnerablities
#
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113004");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-27 14:27:13 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-3431", "CVE-2015-3432");
  script_bugtraq_id(74596);

  script_name("Pydio version before 6.0.7 multiple vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"The host is running and older version of Pydio which is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Pydio version <6.0.7 is prone to XSS and command injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker change the contents of the Webpage and send a link
  to victims. Furthermore, an attacker could run arbitrary commands on the host.");

  script_tag(name:"affected", value:"Pydio version before 6.0.7.");

  script_tag(name:"solution", value:"Update to Pydio version 6.0.7.");

  script_xref(name:"URL", value:"https://pydio.com/en/community/releases/pydio-core/pydio-607-security-release");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "6.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.7" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
