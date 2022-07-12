###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_openmeetings_xml_valid_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Apache OpenMeetings Missing XML Validation Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112064");
  script_version("$Revision: 14175 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-10-05 14:56:22 +0200 (Thu, 05 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-7664");
  script_bugtraq_id(99576);

  script_name("Apache OpenMeetings Missing XML Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_detect.nasl");
  script_require_ports("Services/www", 5080);
  script_mandatory_keys("Apache/Openmeetings/Installed");

  script_tag(name:"summary", value:"Apache OpenMeetings a missing XML validation vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"In Apache OpenMeetings uploaded XML documents were not correctly validated.");
  script_tag(name:"affected", value:"Apache OpenMeetings version 3.1.0 up to 3.2.1");
  script_tag(name:"solution", value:"Update your software to version 3.3.0 to fix the issue");

  script_xref(name:"URL", value:"https://openmeetings.apache.org/security.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe = "cpe:/a:apache:openmeetings";

if(!port = get_app_port(cpe:cpe)){
  exit(0);
}

if(!ver = get_app_version(cpe:cpe, port:port)){
  exit(0);
}

if(version_in_range(version:ver, test_version:"3.1.0", test_version2:"3.2.1")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.3.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
