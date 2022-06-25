###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_dos_vuln_feb10.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Squid 'lib/rfc1035.c' Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updataed By:
# Antu Sanadi <santu@secpod.com> on 2010-02-16
# included the port check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800460");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0308");
  script_name("Squid 'lib/rfc1035.c' Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38455");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38451");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56001");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0260");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2010_1.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/HEAD/changesets/12597.patch");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v3/3.0/changesets/squid-3.0-9163.patch");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v3/3.1/changesets/squid-3.1-9853.patch");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of service
  via a crafted auth header.");
  script_tag(name:"affected", value:"Squid Version 2.x, 3.0 to 3.0.STABLE22, and  3.1 to 3.1.0.15");
  script_tag(name:"insight", value:"The flaw is due to error in 'lib/rfc1035.c' when, processing crafted DNS
  packet that only contains a header.");
  script_tag(name:"summary", value:"This host is running Squid and is prone to Denial of Service
  vulnerability.");
  script_tag(name:"solution", value:"Apply patches from the references or upgrade to the squid version 3.0.STABLE23 or 3.1.0.16.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^2\.0" ||
    version_in_range( version:vers, test_version:"3.1", test_version2:"3.1.0.15" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE22" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE23/3.1.0.16" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );