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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117680");
  script_version("2021-09-16T12:27:58+0000");
  script_cve_id("CVE-2017-9791");
  script_bugtraq_id(99484);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-17 10:28:54 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 19:31:00 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2021-09-16 12:25:44 +0000 (Thu, 16 Sep 2021)");
  script_name("Apache Struts RCE Vulnerability (S2-048) - Version Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://www.checkpoint.com/defense/advisories/public/2017/cpai-2017-0558.html");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-048");
  script_xref(name:"URL", value:"https://struts.apache.org/announce-2017.html#a20170707");
  script_xref(name:"Advisory-ID", value:"S2-048");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-058");
  script_xref(name:"Advisory-ID", value:"S2-058");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to perform a RCE attack with a malicious field
  value when using the Struts 2 Struts 1 plugin and it's a Struts 1 action and the value is a part
  of a message presented to the user, i.e. when using untrusted input as a part of the error message
  in the ActionMessage class.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.3.x with Struts 1 plugin and Struts 1 action.");

  script_tag(name:"solution", value:"As a mitigation always use resource keys instead of passing a
  raw message to the ActionMessage as shown in the references, never pass a raw value directly.");

  # nb: Struts 1 plugin and Struts 1 action required. Also mitigation only possible on code side...
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^2\.3\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);