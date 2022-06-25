###############################################################################
# OpenVAS Vulnerability Test
#
# QNAP NAS Photo Station Cross Site Scripting Vulnerability (nas-201804-23)
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

CPE = "cpe:/o:qnap:qts_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813165");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-13073");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-07 10:36:25 +0530 (Mon, 07 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QNAP NAS Photo Station Cross Site Scripting Vulnerability (nas-201804-23)");

  script_tag(name:"summary", value:"This host is running QNAP NAS Photo Station
  and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient sanitization
  of user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code.");

  script_tag(name:"affected", value:"QNAP Photo Station versions 5.4.3 and earlier
  for QTS 4.3.x, Photo Station versions 5.2.7 and earlier for QTS 4.2.x");

  script_tag(name:"solution", value:"Update QNAP Photo Station to version 5.4.4
  or later for QTS 4.3.x, and to version 5.2.8 or later for QTS 4.2.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201804-23");
  script_xref(name:"URL", value:"https://www.qnap.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("QNAP/QTS/PS/baseQTSVer", "QNAP/QTS/PhotoStation/detected");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!qtsPort = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: qtsPort))
  exit(0);

qnapQtsVer = get_kb_item("QNAP/QTS/PS/baseQTSVer");

if(qnapQtsVer =~ "^(4\.3\.)") {
  if(version_is_less(version:version, test_version:"5.4.4"))
    fix = "5.4.4";
} else if (qnapQtsVer =~ "^(4\.2\.)") {
  if(version_is_less(version:version, test_version:"5.2.8"))
    fix = "5.2.8";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:qtsPort);
  exit(0);
}

exit(0);
