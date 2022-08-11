###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Denial of Service Vulnerability Sep17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811695");
  script_version("2019-05-17T11:35:17+0000");
  script_cve_id("CVE-2017-1519");
  script_bugtraq_id(100688);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-14 13:42:29 +0530 (Thu, 14 Sep 2017)");

  script_name("IBM DB2 Denial of Service Vulnerability Sep17");

  script_tag(name:"summary", value:"This host is running IBM DB2 and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  implementation of DB2 connect server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote user to cause disruption of service for DB2 Connect Server setup
  with a particular configuration.");

  script_tag(name:"affected", value:"IBM DB2 versions 10.5 before 10.5 FP8, IBM DB2 versions 11.1.2.2 before
  11.1.2.2 FP2");

  script_tag(name:"solution", value:"Apply the appropriate fix from reference link");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22007183");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if (version =~ "^10\.05\.") {
  if (version_is_less(version: version, test_version: "10.05.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.05.8");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

if (version =~ "^11\.01\.") {
  if (version_is_less(version: version, test_version: "11.01.2.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "11.01.2.22");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
