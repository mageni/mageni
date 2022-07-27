# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:log4j";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117843");
  script_version("2021-12-17T14:24:48+0000");
  script_tag(name:"last_modification", value:"2021-12-17 14:24:48 +0000 (Fri, 17 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-17 14:18:40 +0000 (Fri, 17 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-4104");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Log4j 1.2.x RCE Vulnerability (Windows, Dec 2021) - Version Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_log4j_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/log4j/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Log4j is prone to a remote code execution (RCE)
  vulnerability in JMSAppender.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"JMSAppender in Log4j 1.2 is vulnerable to deserialization of
  untrusted data when the attacker has write access to the Log4j configuration. The attacker can
  provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender
  to perform JNDI requests that result in remote code execution in a similar fashion to
  CVE-2021-44228.

  Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is
  not the default.");

  script_tag(name:"affected", value:"Apache Log4j version 1.2.x.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it
  addresses numerous other issues from the previous versions.");

  script_xref(name:"URL", value:"https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^1\.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
