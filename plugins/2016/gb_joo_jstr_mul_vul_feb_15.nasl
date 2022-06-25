###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joo_jstr_mul_vul_feb_15.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Joomla J2Store 3.1.6 Multiple SQL Injection Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107024");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2015-6513");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"creation_date", value:"2016-07-07 06:40:16 +0200 (Thu, 07 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla J2Store 3.1.6 Multiple SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is running Jommla J2Store and is prone to multiple SQL injection vulnerabilities.");
  script_tag(name:"insight", value:"The first vulnerability was in the sortby parameter within a request made
  while searching for products. The second vulnerability was in an advanced search multipart form request,
  within the manufacturer_ids parameters.");
  script_tag(name:"vuldetect", value:"The script detects the version of joomla J2Store component on remote host and tells whether it is vulnerable or not.");
  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to execute arbitrary SQL commands via the (1) sortby or (2) manufacturer_ids[] parameter to index.php.");
  script_tag(name:"affected", value:"J2Store v3.1.6 and previous versions.");
  script_tag(name:"solution", value:"Fixed in J2Store v3.1.7 version.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132658/Joomla-J2Store-3.1.6-SQL-Injection.html");
  script_xref(name:"URL", value:"http://j2store.org/download-j2store/j2store-v3-3-1-7.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:appPort)){
  exit(0);
}

url = dir + '/Joomla/administrator/components/com_j2store/com_j2store.xml';
sndReq = http_get( item: url, port:appPort );
rcvRes = http_keepalive_send_recv( port: appPort, data:sndReq, bodyonly:FALSE );
if ( rcvRes !~ "<extension version" && "J2Store" >!< rcvRes && "Joomla" >!< rcvRes) exit ( 0 );

if(ve = egrep( pattern:'<version>([0-9])+', string:rcvRes) ) {
  tmpVer = eregmatch ( pattern:'<version>(([0-9])[.]([0-9])[.]([0-9]))', string: ve);
}

if(tmpVer[1] ) {
  jstrVer = tmpVer[1];
}

if(version_is_less (version: jstrVer, test_version: "3.1.7")) {
  report = report_fixed_ver(installed_version:jstrVer, fixed_version:"3.1.7 or higher");
  security_message(data:report, port:appPort);
  exit(0);
}

exit(99);