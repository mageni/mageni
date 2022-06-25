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

CPE = "cpe:/o:huawei:ar3200_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143972");
  script_version("2020-05-26T04:49:35+0000");
  script_tag(name:"last_modification", value:"2020-05-26 09:19:23 +0000 (Tue, 26 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 03:19:08 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-5386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: CGI Application Vulnerability (huawei-sa-20171129-01-httpproxy)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Huawei AR3200 is prone to a CGI application vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some open source software used by Huawei does not attempt to address
  RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence
  of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to
  redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in
  an HTTP request.");

  script_tag(name:"impact", value:"Remote attackers can redirect an application's outbound HTTP traffic to an
  arbitrary proxy server via a crafted Proxy header in an HTTP request by exploit this vulnerability.");

  script_tag(name:"affected", value:"Huawei AR3200.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171129-01-httpproxy-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(infos["version"]);

if (version == "V200R005C30" || version == "V200R005C32" || version == "V200R006C10" ||
    version == "V200R006C11" || version == "V200R006C12" || version == "V200R006C13" ||
    version == "V200R006C15" || version == "V200R006C16" || version == "V200R006C17" ||
    version == "V200R007C00") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C50");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
