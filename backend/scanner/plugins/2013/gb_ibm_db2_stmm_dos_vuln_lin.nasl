###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 STMM Denial Of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803766");
  script_version("2019-05-17T11:35:17+0000");
  script_cve_id("CVE-2011-1373");
  script_bugtraq_id(50686);
  script_tag(name:"cvss_base", value:"1.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2013-09-30 17:51:03 +0530 (Mon, 30 Sep 2013)");

  script_name("IBM DB2 STMM Denial Of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running IBM DB2 and is prone to denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM DB2 9.7 FP5 or later.");

  script_tag(name:"insight", value:"The flaw is due an error when the Self Tuning Memory Manager (STMM) feature
and the AUTOMATIC DATABASE_MEMORY setting are configured.");

  script_tag(name:"affected", value:"IBM DB2 version 9.7 before FP5 on Linux.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to allows local users to cause a
denial of service (daemon crash) via unknown vectors.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71043");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70473");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("IBM-DB2/installed", "Host/runs_unixoide");

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
  if (version_is_less(version: version, test_version: "09.07.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.07.5");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
