###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Multiple Denial of Service Vulnerabilities-May18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813401");
  script_version("2019-05-17T11:35:17+0000");
  script_cve_id("CVE-2018-5736", "CVE-2018-5737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-22 09:25:41 +0530 (Tue, 22 May 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Multiple Denial of Service Vulnerabilities-May18");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in zone database reference counting while attempting several
    transfers of a slave zone in quick succession.

  - An error in the implementation of the new serve-stale feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure or degradation).");

  script_tag(name:"affected", value:"ISC BIND versions 9.12.0 and 9.12.1");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.12.1-P2 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01606/0");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01602/0");
  script_xref(name:"URL", value:"https://www.isc.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed", "bind/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_proto(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if(version == "9.12.0" || version == "9.12.1")
{
  report = report_fixed_ver(installed_version: version, fixed_version: "9.12.1-P2");
  security_message(port:port, data: report, proto: proto);
  exit(0);
}
exit(0);
