# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143504");
  script_version("2020-02-11T08:25:04+0000");
  script_tag(name:"last_modification", value:"2020-02-11 08:25:04 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-11 07:27:24 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-8656", "CVE-2020-8657");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Eyes Of Network (EON) Multiple API Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/api/version");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities over the API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities:

  - SQL injection vulnerability allowing an unauthenticated attacker to perform various tasks such as
    authentication bypass (CVE-2020-8656)

  - Hardcoded EONAPI_KEY allowing an attacker to calculate/guess the admin access token (CVE-2020-8657)");

  script_tag(name:"affected", value:"Eyes Of Network API version 2.4.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 11th February, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonapi/issues/16");
  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonapi/issues/17");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/156266/EyesOfNetwork-5.3-Remote-Code-Execution.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (!version = get_kb_item("eyesofnetwork/api/version"))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
