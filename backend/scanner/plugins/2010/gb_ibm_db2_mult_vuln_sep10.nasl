###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Multiple Vulnerabilities (Sep10)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801503");
  script_version("2019-05-17T11:35:17+0000");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-3193", "CVE-2010-3194");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("IBM DB2 Multiple Vulnerabilities (Sep10)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41218");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61445");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2225");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21432298");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21426108");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security
  restrictions, gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM DB2 versions prior to 9.1 Fix Pack 9,
  IBM DB2 versions prior to 9.5 Fix Pack 6 and
  IBM DB2 versions prior to 9.7 Fix Pack 2");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An unspecified error related to 'DB2STST' program, which has unknown impact and attack vectors.

  - An error related to 'DB2DART' program, which could be exploited to overwrite files owned by the instance owner.");

  script_tag(name:"solution", value:"Update DB2 9.1 Fix Pack 9, 9.5 Fix Pack 6, or 9.7 Fix Pack 2");

  script_tag(name:"summary", value:"The host is running IBM DB2 and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if (version =~ "^09\.07\.") {
  if (version_is_less(version: version, test_version: "09.07.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.07.2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

if (version =~ "^09\.05\.") {
  if (version_is_less(version: version, test_version: "09.05.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.05.06");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

if (version =~ "^09\.01\.") {
  if (version_is_less(version: version, test_version: "09.01.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.01.9");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
