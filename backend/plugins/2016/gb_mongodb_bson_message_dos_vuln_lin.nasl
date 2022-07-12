###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_bson_message_dos_vuln_lin.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# MongoDB BSON Message Handling Remote Denial-of-Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808147");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2015-1609");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 10:43:02 +0530 (Tue, 07 Jun 2016)");
  script_name("MongoDB BSON Message Handling Remote Denial-of-Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with MongoDB
  and is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to error in mongod that is
  triggered when handling a specially crafted BSON message.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"MongoDB version 2.4.12 and earlier,
  2.6.7 and earlier, and 3.0.0-rc8 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.4.13 or
  2.6.8 or 3.0.0-rc9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.mongodb.org/about/alerts/");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-17264");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-012");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/mongodb", 27017);
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.mongodb.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mongodbPort = get_app_port(cpe:CPE)) exit(0);

if(!ver = get_app_version(cpe:CPE, port:mongodbPort)) exit(0);

##Replace '-' by '.' in version
if("-rc" >< ver){
 mongodbversion = ereg_replace(pattern:"-", replace:".", string:ver);
}

if(mongodbversion)
{
  if(version_in_range(version:mongodbversion, test_version:"2.6", test_version2:"2.6.7"))
  {
    fix = "2.6.8";
    VULN = TRUE ;
  }

  else if(version_in_range(version:mongodbversion, test_version:"2.4", test_version2:"2.4.12"))
  {
    fix = "2.4.13";
    VULN = TRUE ;
  }

  else if(version_is_equal(version:mongodbversion, test_version:"3.0.0.rc8"))
  {
    fix = "3.0.0.rc9";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:mongodbversion, fixed_version:fix);
    {
      security_message(data:report, port:mongodbPort);
      exit(0);
    }
  }
}