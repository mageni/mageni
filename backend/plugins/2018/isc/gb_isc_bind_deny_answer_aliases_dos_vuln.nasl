###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND 'deny-answer-aliases' Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.813750");
  script_version("2019-05-17T11:35:17+0000");
  script_cve_id("CVE-2018-5740");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-10 12:14:44 +0530 (Fri, 10 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND 'deny-answer-aliases' Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a defect in the
  feature 'deny-answer-aliases' which leads to assertion failure in 'name.c'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure).");

  script_tag(name:"affected", value:"ISC BIND versions 9.7.0 through 9.8.8,
  9.9.0 through 9.9.13, 9.10.0 through 9.10.8, 9.11.0 through 9.11.4,
  9.12.0 through 9.12.2 and 9.13.0 through 9.13.2.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.13-P1 or
  9.10.8-P1 or 9.11.4-P1 or 9.12.2-P1 or 9.11.3-S3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01639/0");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01646/81/BIND-9.11.3-S3-Release-Notes.html");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01645/81/BIND-9.12.2-P1-Release-Notes.html");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01644/81/BIND-9.11.4-P1-Release-Notes.html");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01643/81/BIND-9.10.8-P1-Release-Notes.html");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01642/81/BIND-9.9.13-P1-Release-Notes.html");
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

if(version !~ "^9\.") {
  exit(0);
}

if(version =~ "9\.11\.[0-9]\.S[0-9]") {
  if (version_in_range(version: version, test_version: "9.11.0.S0", test_version2: "9.11.3.S2")) {
    fix = "9.11.3-S3";
  }
} else
{
  if(version_in_range(version: version, test_version: "9.7.0", test_version2: "9.8.8") ||
     version_in_range(version: version, test_version: "9.9.0", test_version2: "9.9.13")){
    fix = "9.9.13-P1";
  }

  else if(version_in_range(version: version, test_version:"9.10.0", test_version2:"9.10.8")){
    fix = "9.10.8-P1";
  }

  else if(version_in_range(version: version, test_version:"9.11.0", test_version2:"9.11.4")){
    fix = "9.11.4-P1";
  }

  else if(version_in_range(version: version, test_version:"9.12.0", test_version2:"9.12.2")){
    fix = "9.12.2-P1";
  }

  else if(version_in_range(version: version, test_version:"9.13.0", test_version2:"9.13.2")){
    fix = "9.14";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(port: port, data: report, proto: proto);
  exit(0);
}
exit(0);
