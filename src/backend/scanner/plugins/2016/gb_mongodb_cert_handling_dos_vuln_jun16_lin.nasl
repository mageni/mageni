###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_cert_handling_dos_vuln_jun16_lin.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# MongoDB mongod Malformed X.509 Certificate Handling Remote DoS Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808151");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2014-3971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 10:43:02 +0530 (Tue, 07 Jun 2016)");
  script_name("MongoDB mongod Malformed X.509 Certificate Handling Remote DoS Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with MongoDB
  and is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of
  X.509 Certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"MongoDB version 2.6.x before 2.6.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-13753");
  script_xref(name:"URL", value:"https://github.com/mongodb/mongo/commit/c151e0660b9736fe66b224f1129a16871165251b");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/mongodb", 27017);
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.mongodb.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mbPort = get_app_port(cpe:CPE)) exit(0);

if(!ver = get_app_version(cpe:CPE, port:mbPort)) exit(0);

if(ver =~ "(^2\.6)")
{
  if(version_is_less(version:ver, test_version:"2.6.2"))
  {
    report = report_fixed_ver(installed_version:ver, fixed_version:"2.6.2");
    security_message(data:report, port:mbPort);
    exit(0);
  }
}
