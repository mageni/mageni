# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.811315");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2015-5209");
  script_bugtraq_id(82550);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-08-31 13:39:09 +0530 (Thu, 31 Aug 2017)");
  script_name("Apache Struts 'top' Object Access Security Bypass Vulnerability (S2-026)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-026");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033908");
  script_xref(name:"URL", value:"https://vuldb.com/?id.105878");
  script_xref(name:"Advisory-ID", value:"S2-026");

  script_tag(name:"summary", value:"Apache Struts is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to due to an incorrect handling of
  the 'top' object in specially crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass
  certain security restrictions and perform unauthorized actions. This may lead to further
  attacks.");

  script_tag(name:"affected", value:"Apache Struts 2.x before 2.3.24.1.");

  script_tag(name:"solution", value:"Update to version 2.3.24.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.3.24")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.3.24.1", install_path:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);