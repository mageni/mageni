###############################################################################
# OpenVAS Vulnerability Test
#
# Yahoo! Messenger 'YahooBridgeLib.dll' ActiveX Control DOS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801150");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4171");
  script_bugtraq_id(37007);
  script_name("Yahoo! Messenger 'YahooBridgeLib.dll' ActiveX Control DOS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_yahoo_msg_detect.nasl", "yahoo_msg_running.nasl");
  script_mandatory_keys("YahooMessenger/Ver");
  script_require_ports("Services/yahoo_messenger", 5101);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause Denial of
  Service condition on the affected application.");

  script_tag(name:"affected", value:"Yahoo! Messenger version 9.x to 9.0.0.2162 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to a NULL pointer dereference error in 'RegisterMe()' method
  in 'YahooBridgeLib.dll', which can be exploited by causing the victim to visit a specially crafted web page.");

  script_tag(name:"solution", value:"Upgrade to Yahoo! Messenger version 10.0.0.1270 or later");

  script_tag(name:"summary", value:"This host is installed with Yahoo! Messenger and is prone to a Denial
  of Service Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");

ymsgPort = get_kb_item( "Services/yahoo_messenger" );
if( ! ymsgPort ) ymsgPort = 5101;
if( ! get_port_state( ymsgPort ) ) exit( 0 );

ymsgVer = get_kb_item( "YahooMessenger/Ver" );
if( ! ymsgVer ) exit( 0 );

if( version_in_range( version:ymsgVer, test_version:"9.0", test_version2:"9.0.0.2162" ) ) {
  report = report_fixed_ver( installed_version:ymsgVer, fixed_version:"10.0.0.1270" );
  security_message( port:ymsgPort, data:report );
  exit( 0 );
}

exit( 99 );