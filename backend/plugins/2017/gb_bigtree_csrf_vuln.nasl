###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_csrf_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# BigTree CMS Multiple CSRF Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:bigtree:bigtree";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106666");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 13:15:28 +0700 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2017-6914", "CVE-2017-6915", "CVE-2017-6916", "CVE-2017-6917", "CVE-2017-6918");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BigTree CMS Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("BigTree/Installed");

  script_tag(name:"summary", value:"BigTree CMS is prone to multiple CSRF vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BigTree CMS is prone to multiple CSRF vulnerabilities:

  - CSRF with the id parameter to the admin/ajax/users/delete/ page. (CVE-2017-6914)

  - CSRF with the colophon parameter to the admin/settings/update/ page. (CVE-2017-6915)

  - CSRF with the nav-social[#] parameter to the admin/settings/update/ page. (CVE-2017-6916)

  - CSRF with the value parameter to the admin/settings/update/ page. (CVE-2017-6917)

  - CSRF with the value[#][*] parameter to the admin/settings/update/ page. (CVE-2017-6918)");

  script_tag(name:"affected", value:"BigTree 4.1.18 and 4.2.16");

  script_tag(name:"solution", value:"Update to version 4.2.17 or later.");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/275");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
