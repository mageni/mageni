###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_routers_information_disclosure.nasl 11768 2018-10-05 14:07:38Z cfischer $
#
# Netgear DGN2200 & DGND3700 Admin Password Disclosure
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112333");
  script_version("$Revision: 11768 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-25 09:39:41 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-5649");

  script_name("Netgear DGN2200 & DGND3700 Admin Password Disclosure");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_dgn2200_detect.nasl", "gb_netgear_dgnd3700_detect.nasl");
  script_mandatory_keys("netgear/router/detected");

  script_tag(name:"summary", value:"A vulnerability exists in the 'BSW_cxttongr.htm' page which can allow a remote
  attacker to access this page without any authentication.");

  script_tag(name:"vuldetect", value:"Sends a request to the vulnerable page and tries to obtain the admin password.");

  script_tag(name:"insight", value:"When the request is processed, it
  exposes the admin's password in clear text before it gets redirected to
  absw_vfysucc.cgia.");

  script_tag(name:"impact", value:"An attacker can use this password to gain administrator
  access of the targeted routers web interface.");

  script_tag(name:"affected", value:"Netgear DGN2200 running firmware version DGN2200-V1.0.0.50_7.0.50.

  Netgear DGND3700 running firmware version DGND3700-V1.0.0.17_1.0.17.");
  script_tag(name:"solution", value:"Netgear has released firmware version 1.0.0.52 for DGN2200 & 1.0.0.28 for
  DGND3700 to address this issue.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/140342/Netgear-DGN2200-DGND3700-WNDR4500-Information-Disclosure.html");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

CPE = make_list( 'cpe:/h:netgear:dgn2200', 'cpe:/h:netgear:dgnd3700' );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

res = http_get_cache( port: port, item: "/BSW_cxttongr.htm" );

if( vuln = eregmatch( pattern: '<td colspan="2"><b>Success "(.+)"\r', string: res ) ) {
  report = "It was possible to obtain the admin password: '" + vuln[1] + "'.";
  security_message( port: port, data: report);
  exit( 0 );
}

exit( 99 );
