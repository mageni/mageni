###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_server_tls_handshake_dos_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Apache Traffic Server (ATS) TLS Handshake DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:apache:traffic_server';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812524");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2017-7671");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-28 11:37:03 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache Traffic Server (ATS) TLS Handshake DOS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Traffic
  Server and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in TLS
  handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Apache Traffic Server 5.2.0 to 5.3.2,

  Apache Traffic Server 6.0.0 to 6.2.0 and

  Apache Traffic Server 7.0.0");

  script_tag(name:"solution", value:"5.x users upgrade to 7.1.2 or later versions,

  6.x users upgrade to 6.2.2 or later versions and

  7.x users upgrade to 7.1.2 or later versions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q1/197");
  script_xref(name:"URL", value:"https://github.com/apache/trafficserver/pull/1941");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");
  script_xref(name:"URL", value:"http://trafficserver.apache.org/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
atsVer = infos['version'];
atsPath = infos['location'];

if(atsVer == "7.0.0"){
  fix = "7.1.2";
}
else if(atsVer =~ "^(5\.2)")
{
  if(version_in_range(version:atsVer, test_version: "5.2", test_version2: "5.3.2")){
  fix =  "7.1.2";
  }
}
else if(atsVer =~ "^(6\.0)")
{
  if(version_in_range(version:atsVer, test_version: "6.0", test_version2: "6.2.0")){
  fix =  "6.2.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version: atsVer, fixed_version: fix, install_path:atsPath);
  security_message(port: port, data: report);
  exit(0);
}
