##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_1_4_33.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Memcached < 1.4.33 Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:memcached:memcached";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140042");
  script_version("$Revision: 12363 $");
  script_cve_id("CVE-2016-8704", "CVE-2016-8705", "CVE-2016-8706");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-02 14:57:47 +0100 (Wed, 02 Nov 2016)");
  script_name("Memcached < 1.4.33 Multiple Remote Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"https://github.com/memcached/memcached/wiki/ReleaseNotes1433");
  script_xref(name:"URL", value:"http://blog.talosintel.com/2016/10/memcached-vulnerabilities.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("Memcached/detected");

  script_tag(name:"affected", value:"Memcached < 1.4.33");

  script_tag(name:"insight", value:"These vulnerabilities manifest in various Memcached functions that are
  used in inserting, appending, prepending, or modifying key-value data pairs. Systems which also have
  Memcached compiled with support for SASL authentication are also vulnerable to a third flaw due to how
  Memcached handles SASL authentication commands.");

  script_tag(name:"solution", value:"Update to Memcached 1.4.33 or newer.");

  script_tag(name:"summary", value:"Multiple integer overflow vulnerabilities exist within Memcached that
  could be exploited to achieve remote code execution on the targeted system.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

vers  = infos["version"];
proto = infos["proto"];

if( version_is_less( version:vers, test_version:"1.4.33" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.33" );
  security_message( port:port, proto:proto, data:report );
  exit( 0 );
}

exit( 99 );
