###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_dbshell_info_disclose_vuln_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# MongoDB Client 'dbshell' Information Disclosure Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809350");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-6494");
  script_bugtraq_id(92204);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 15:38:52 +0530 (Thu, 13 Oct 2016)");
  script_name("MongoDB Client 'dbshell' Information Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with MongoDB
  and is prone to information disclousre vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to mongodb-clients stores
  its history in '~/.dbshell', this file is created with permissions 0644. Home
  folders are world readable as well.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to obtain sensitive information by reading .dbshell history files.");

  script_tag(name:"affected", value:"MongoDB version 2.4.10 on Linux");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 3.0, or 3.2
  or 3.3.14, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-25335");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832908");

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

if(version_is_equal(version:mongodbversion, test_version:"2.4.10"))
{
  report = report_fixed_ver(installed_version:mongodbversion, fixed_version:"3.0 or 3.2 or 3.3.14");
  security_message(data:report, port:mbPort);
  exit(0);
}
