###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! < 3.8.12 ACL Violation Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112372");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-15881");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-30 10:12:03 +0200 (Thu, 30 Aug 2018)");

  script_name("Joomla! < 3.8.12 ACL Violation Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to ACL violation in custom fields.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Inadequate checks regarding disabled fields can lead to an ACL violation.");

  script_tag(name:"affected", value:"Joomla! CMS versions 3.7.0 through 3.8.11");

  script_tag(name:"solution", value:"Upgrade to version 3.8.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/745-20180803-core-acl-violation-in-custom-fields.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.joomla.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:joomla:joomla";

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
ver = infos['version'];
path = infos['location'];

if(version_in_range(version:ver, test_version:"3.7.0", test_version2:"3.8.11")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.8.12", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
