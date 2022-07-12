# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144911");
  script_version("2020-12-17T07:22:05+0000");
  script_tag(name:"last_modification", value:"2020-12-17 11:08:11 +0000 (Thu, 17 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-17 06:34:07 +0000 (Thu, 17 Dec 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-29254");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Tiki Wiki <= 21.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"summary", value:"Tiki Wiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Local (php) File Inclusion: In TikiWiki, an user can be given the permission to edit .tpl templates.
  This feature can be abused to escalate the users privileges by inserting the following pieceof smarty
  code: {include file='../db/local.php'}. The code snippet includes Tiki Wikis database configuration
  file and displays it in the pages source code. Any other www-data readable file like '/etc/passwd' can
  be included as well.

  - Cross-Side-Request-Forgery (CSRF): Tiki Wiki allows templates to be edited without CSRF protection.
  This could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack
  and perform arbitrary actions on an affected system. The vulnerability is due to insufficient CSRF protections
  for the web-based management interface of the affected system. An attacker could exploit this vulnerability
  by persuading a user of the interface to follow a maliciously crafted link. (CVE-2020-29254)

  - Information Exposure: An user who is able to edit template files can use smarty code to include Files like
  the database configuration file which allows access to TikiWikis Database.");

  script_tag(name:"impact", value:"- Local (php) File Inclusion: The config file displays TikiWikis database
  credentials in cleartext.

  - Cross-Side-Request-Forgery (CSRF): A successful exploit could allow the
  attacker to perform arbitrary actions on an affected system with the privileges of the user. These action
  include allowing attackers to submit their own code through an authenticated user resulting in local file
  Inclusion. If an authenticated user who is able to edit Tiki Wiki templates visits an malicious website,
  template code can be edited.

  - Information Exposure: The User can authenticate against it and simply give itself admin privileges or
  compromise the administrator account.");

  script_tag(name:"affected", value:"Tiki Wiki through version 21.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th December, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/S1lkys/CVE-2020-29254");
  script_xref(name:"URL", value:"https://github.com/S1lkys/CVE-2020-29254/blob/main/Tiki-Wiki%2021.2%20by%20Maximilian%20Barz.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "21.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
