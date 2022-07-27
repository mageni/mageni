###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_torrent_trader_classic_mult_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# TorrentTrader Classic Multiple Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:torrenttrader:torrenttrader_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800522");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2156", "CVE-2009-2157", "CVE-2009-2158",
                "CVE-2009-2159", "CVE-2009-2160", "CVE-2009-2161");
  script_bugtraq_id(35369);
  script_name("TorrentTrader Classic Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_torrent_trader_classic_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("torrenttraderclassic/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504294/100/0/threaded");

  script_tag(name:"affected", value:"TorrentTrader Classic version 1.09 and prior.");

  script_tag(name:"insight", value:"Multiple flaws due to, improper validation of user-supplied input data to
  different parameters and Access to the '.php' scripts are not properly restricted.");

  script_tag(name:"solution", value:"Upgrade to TorrentTrader Classic version 2.0.6 or later.");

  script_tag(name:"summary", value:"This host is running TorrentTrader Classic and is prone to
  multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject and execute
  arbitrary SQL queries via malicious SQL code, and can gain sensitive
  information about remote system user credentials and database.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/torrenttrader");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos['version'];
dir = infos['location'];
if( dir == "/" ) dir = "";

url = dir + "/upload/browse.php?wherecatin=waraxe";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "Unknown column 'waraxe' in 'where clause'" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_less_equal( version:vers, test_version:"1.09" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.6" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );