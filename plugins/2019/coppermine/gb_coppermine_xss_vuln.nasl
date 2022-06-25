##############################################################################
# OpenVAS Vulnerability Test
#
# Coppermine < 1.5.48 XSS Vulnerability
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

CPE = "cpe:/a:coppermine:coppermine_photo_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141958");
  script_version("2019-05-10T08:44:08+0000");
  script_tag(name:"last_modification", value:"2019-05-10 08:44:08 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-05 11:17:46 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-14478");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Coppermine < 1.5.48 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("coppermine_detect.nasl");
  script_mandatory_keys("coppermine_gallery/installed");

  script_tag(name:"summary", value:"Coppermine is prone to multiple reflected cross-site scripting
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Coppermine prior to version 1.5.48.");

  script_tag(name:"solution", value:"Update to version 1.5.48 or later.");

  script_xref(name:"URL", value:"https://www.netsparker.com/web-applications-advisories/ns-18-050-cross-site-scripting-in-coppermine/");
  script_xref(name:"URL", value:"http://forum.coppermine-gallery.net/index.php/topic,79577.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.48");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
