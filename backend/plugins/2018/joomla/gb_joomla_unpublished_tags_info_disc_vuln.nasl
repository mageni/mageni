###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Core 'Unpublished Tags' Information Disclosure Vulnerability (20180503)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813407");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11327");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-23 12:12:14 +0530 (Wed, 23 May 2018)");

  script_name("Joomla! Core 'Unpublished Tags' Information Disclosure Vulnerability (20180503)");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to an information disclosure
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate checks for users to see the names of tags
that were either unpublished or published with restricted view permission.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to
potentially sensitive information.");

  script_tag(name:"affected", value:"Joomla core versions 3.1.0 through 3.8.7");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/731-20180503-core-information-disclosure-about-unpublished-tags.html");
  script_xref(name:"URL", value:"https://www.joomla.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:jPort, exit_no_version:TRUE )) exit(0);
jVer = infos['version'];
path = infos['location'];

if(version_in_range(version:jVer, test_version:"3.1.0", test_version2:"3.8.7")) {
  report = report_fixed_ver(installed_version:jVer, fixed_version:"3.8.8", install_path:path);
  security_message(port:jPort, data:report);
  exit(0);
}

exit(0);
