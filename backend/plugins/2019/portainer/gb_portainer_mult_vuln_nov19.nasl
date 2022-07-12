# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114162");
  script_version("2019-11-11T10:22:03+0000");
  script_tag(name:"last_modification", value:"2019-11-11 10:22:03 +0000 (Mon, 11 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-08 16:14:12 +0100 (Fri, 08 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-16872", "CVE-2019-16873", "CVE-2019-16874",
  "CVE-2019-16876", "CVE-2019-16877", "CVE-2019-16878");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Portainer < 1.22.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_portainer_detect.nasl");
  script_mandatory_keys("portainer/detected");

  script_tag(name:"summary", value:"Portainer is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Portainer is prone to multiple vulnerabilities:

  - An Unrestricted Host Filesystem Access vulnerability exists in Stack creation feature
  in Portainer. Successful exploitation of this vulnerability would allow an
  authenticated user to gain full permission on the host filesystem. (CVE-2019-16872)

  - A Stored Cross-Site Scripting vulnerability exists in the isteven-multi-select component
  in Portainer. Successful exploitation of this vulnerability would allow authenticated users
  to inject arbitrary Javascript into Portainer pages viewed by other users. (CVE-2019-16873)

  - An Improper Access Control vulnerability exists in the RBAC extension in Portainer.
  Successful exploitation of this vulnerability would allow Helpdesk users to access sensitive
  information via the volume browsing feature. (CVE-2019-16874)

  - A path traversal vulnerability exists in Portainer. Successful exploitation of this
  vulnerability would allow an authenticated user to upload files to an arbitrary location. (CVE-2019-16876)

  - An authorization bypass vulnerability exists in Portainer. Successful exploitation of this
  vulnerability would allow an authenticated user to gain full permission on a host filesystem
  via the Host Management API. (CVE-2019-16877)

  - A Stored Cross-Site Scripting vulnerability exists in the file removal confirmation modal
  in Portainer. Successful exploitation of this vulnerability would allow an authenticated user
  to inject arbitrary Javascript into Portainer pages viewed by other users. (CVE-2019-16878)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Portainer versions before 1.22.1.");

  script_tag(name:"solution", value:"Update to Portainer 1.22.1 or later.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:portainer:portainer";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: version, test_version: "1.22.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.22.1");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
