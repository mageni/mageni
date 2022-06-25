###############################################################################
# OpenVAS Vulnerability Test
# $Id: pdns_jan_10.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PowerDNS Recursor multiple vulnerabilities - Jan10
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100433");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(37653, 37650);
  script_cve_id("CVE-2009-4010", "CVE-2009-4009");
  script_name("PowerDNS Recursor multiple vulnerabilities - Jan10");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37653");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37650");
  script_xref(name:"URL", value:"http://www.powerdns.com/");
  script_xref(name:"URL", value:"http://doc.powerdns.com/powerdns-advisory-2010-02.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508743");

  script_tag(name:"impact", value:"An attacker can exploit the remote cache-poisoning vulnerability to
  divert data from a legitimate site to an attacker-specified site.
  Successful exploits will allow the attacker to manipulate cache data,
  potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
  service attacks.

  Successfully exploiting of the Buffer Overflow vulnerability allows a
  remote attacker to execute arbitrary code with superuser privileges,
  resulting in a complete compromise of the affected computer. Failed
  exploits will cause a denial of service.");
  script_tag(name:"affected", value:"PowerDNS Recursor 3.1.7.1 and earlier are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a remote cache-poisoning vulnerability and to a
  Buffer Overflow Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.1.7.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1.7.2" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );