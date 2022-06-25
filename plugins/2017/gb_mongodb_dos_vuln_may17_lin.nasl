###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_dos_vuln_may17_lin.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# MongoDB Denial of Service Vulnerability - May17 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811058");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2016-3104");
  script_bugtraq_id(94929);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-29 14:40:50 +0530 (Mon, 29 May 2017)");
  script_name("MongoDB Denial of Service Vulnerability - May17 (Linux)");

  script_tag(name:"summary", value:"The host is installed with MongoDB
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'in-memory'
  database representation when authenticating against a non-existent database.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service. In very extreme cases the increase in
  memory consumption may cause mongod to run out of memory and either terminate or
  be terminated by the operating system's OOM killer.");

  script_tag(name:"affected", value:"MongoDB version 2.4 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.6, or 3.0,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-24378");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(!mbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mongodbversion = get_app_version(cpe:CPE, port:mbPort)){
  exit(0);
}

##Replace '-' by '.' in version
if("-rc" >< mongodbversion){
  mongodbversion = ereg_replace(pattern:"-", replace:".", string:mongodbversion);
}

if(mongodbversion == "2.4.0")
{
  report = report_fixed_ver(installed_version:mongodbversion, fixed_version:"2.6.0 or 3.0");
  security_message(data:report, port:mbPort);
  exit(0);
}
