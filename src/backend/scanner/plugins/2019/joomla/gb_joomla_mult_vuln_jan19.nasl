##############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! < 3.9.2 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141895");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-18 13:17:13 +0700 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-6261", "CVE-2019-6262", "CVE-2019-6263", "CVE-2019-6264");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.9.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple vulnerabilities:

  - Inadequate escaping in com_contact leads to a stored XSS vulnerability (CVE-2019-6261)

  - Inadequate checks of the Global Configuration helpurl settings allowed stored XSS (CVE-2019-6262)

  - Inadequate checks of the Global Configuration Text Filter settings allowed stored XSS (CVE-2019-6263)

  - Inadequate escaping in mod_banners leads to a stored XSS vulnerability (CVE-2019-6264)");

  script_tag(name:"affected", value:"Joomla! CMS versions 2.5.0 through 3.9.1.");

  script_tag(name:"solution", value:"Update to version 3.9.2 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/761-20190102-core-stored-xss-in-com-contact");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/763-20190104-core-stored-xss-issue-in-the-global-configuration-help-url");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/762-20190103-core-stored-xss-issue-in-the-global-configuration-textfilter-settings");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/760-20190101-core-stored-xss-in-mod-banners");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
