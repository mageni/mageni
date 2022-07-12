###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_comps_eol.nasl 13874 2019-02-26 11:51:40Z cfischer $
#
# OpenVAS Framework Components End Of Life Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108197");
  script_version("$Revision: 13874 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 12:51:40 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-26 15:00:00 +0200 (Wed, 26 Jul 2017)");
  script_name("OpenVAS Framework Components End Of Life Detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_gsa_detect.nasl", "gb_openvas_manager_detect.nasl", "gb_greenbone_os_detect.nasl");
  script_mandatory_keys("openvas_gvm/framework_component/detected");
  script_exclude_keys("greenbone/gos/detected"); # GOS is already covered via 2013/gb_os_eol.nasl

  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2018-March/000216.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2016-May/000194.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2015-April/000181.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2014-August/000166.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2013-August/000155.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2012-September/000143.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2011-June/000127.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2009-December/000084.html");

  script_tag(name:"summary", value:"The versions of the OpenVAS framework component on the remote host has
  reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of an OpenVAS framework component is not receiving
  any security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update the OpenVAS framework component version on the remote host to a
  still supported version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("version_func.inc");
include("host_details.inc");

if( get_kb_item( "greenbone/gos/detected" ) )
  exit( 0 ); # GOS is already covered via 2013/gb_os_eol.nasl

foreach cpe( make_list( "cpe:/a:greenbone:greenbone_security_assistant", "cpe:/a:openvas:openvas_manager", "cpe:/a:greenbone:greenbone_vulnerability_manager" ) ) {

  if( ! version = get_app_version( cpe:cpe ) )
    continue;

  if( ret = product_reached_eol( cpe:cpe, version:version ) ) {

    if( "security_assistant" >< cpe ) {
      prod_name = "Greenbone Security Assistant";
    } else if( "openvas_manager" >< cpe ) {
      prod_name = "OpenVAS Manager";
    } else if( "greenbone_vulnerability_manager" >< cpe ) {
      prod_name = "Greenbone Vulnerability Manager";
    } else {
      prod_name = "OpenVAS";
    }

    vuln = TRUE;

    report += build_eol_message( name:prod_name,
                                 cpe:cpe,
                                 version:version,
                                 eol_version:ret["eol_version"],
                                 eol_date:ret["eol_date"],
                                 eol_type:"prod" );
    report += '\n';
  }
}

if( vuln ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );