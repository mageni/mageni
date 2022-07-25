# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104180");
  script_version("2022-07-21T09:32:51+0000");
  script_tag(name:"last_modification", value:"2022-07-21 09:32:51 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-05-13 05:48:20 +0000 (Fri, 13 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-20 18:03:00 +0000 (Fri, 20 May 2022)");

  script_cve_id("CVE-2022-29885");

  # nb: Should reflect that this is "just" a generic note
  script_tag(name:"qod_type", value:"general_note");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Apache Tomcat Clustering DoS Vulnerability (May 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability when running with enabled Tomcat clustering over an untrusted network.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The documentation for the EncryptInterceptor incorrectly stated
  it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the
  EncryptInterceptor does provide confidentiality and integrity protection, it does not protect
  against all risks associated with running over any untrusted network, particularly DoS risks.");

  script_tag(name:"affected", value:"- The documentation in Apache Tomcat 8.5.38 through 8.5.78,
  9.0.13 through 9.0.62, 10.0.0-M1 through 10.0.20 and 10.1.0-M1 to 10.1.0-M14

  - Apache Tomcat when running with enabled Tomcat clustering over an untrusted network");

  script_tag(name:"solution", value:"- Don't run Apache Tomcat with enabled Tomcat clustering over
  an untrusted network

  - Update Apache Tomcat to version 10.1.0-M15, 10.0.21, 9.0.63, 8.5.79 or later to receive the
  corrected / updated documentation");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.0-M15");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.21");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.63");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.79");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/548bnqoxvp0rqqq2yyj90l0xvwhq087d");

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

report = report_fixed_ver(installed_version: version, fixed_version: "See solution information", install_path: location);
security_message(port: port, data: report);

# nb: No exit(99); because the underlying "problem" can be only "fixed" if running Tomcat clustering
# only over trusted networks.
exit(0);
