###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tuleap_obj_inj_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Tuleap Object Injection vulnerability before version 9.7
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
  script_oid("1.3.6.1.4.1.25623.1.0.113039");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-24 11:04:55 +0200 (Tue, 24 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-7411");

  script_name("Tuleap Object Injection vulnerability before version 9.7");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tuleap_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tuleap/installed");

  script_tag(name:"summary", value:"Tuleap version 5.0 through 9.6 allows authenticated attackers to execute arbitrary code on the host via an Object Injection vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the host.");
  script_tag(name:"insight", value:"The vulnerability exists because this method is using the unserialize() function with a value that can be arbitrarily manipulated by a user through the REST API interface. This can be exploited to inject arbitrary PHP objects into the application scope, and could allow authenticated attackers to execute arbitrary PHP code via specially crafted serialized objects. Successful exploitation of this vulnerability requires an user account with permissions to create or access artifacts in a tracker.");
  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to execute arbitrary code on the host.");
  script_tag(name:"affected", value:"Tuleap version 5.0 through 9.6");
  script_tag(name:"solution", value:"Update to Tuleap version 9.7");

  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2017-02");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/10/23/3");

  exit(0);
}

CPE = "cpe:/a:enalean:tuleap";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version= get_app_version( cpe: CPE, port: port ) ) exit( 0 );

# version_in_range is not possible here since the highest patch-level (e.g 9.6.99.[0-9]+) is unknown
# test_version2: 9.6 would result in 9.6.10.1 (random example) to be classified as "fixed", which it is not
if( version_is_greater_equal( version: version, test_version: "5.0" ) && version_is_less( version: version, test_version: "9.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.7" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
