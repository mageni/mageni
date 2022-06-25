###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_jira_rce_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atlassian JIRA XXE / Deserialization Vulnerability
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

CPE = 'cpe:/a:atlassian:jira';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106758");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-18 10:31:18 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian JIRA XXE / Deserialization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_atlassian_jira_detect.nasl");
  script_mandatory_keys("atlassian_jira/installed");

  script_tag(name:"summary", value:"The JIRA Workflow Designer Plugin in Atlassian JIRA Server before 6.3.0
improperly uses an XML parser and deserializer, which allows remote attackers to execute arbitrary code, read
arbitrary files, or cause a denial of service via a crafted serialized Java object.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An anonymous user can perform multiple attacks on a vulnerable JIRA
instance that could cause remote code execution, the disclosure of private files or execute a denial of service
attack against the JIRA server. This vulnerability is caused by the way an XML parser and deserializer was used
in JIRA.");

  script_tag(name:"affected", value:"Atlassian JIRA 4.2.4 until 6.2.7.");

  script_tag(name:"solution", value:"Update to version 6.3.0 or later. Please keep in mind that JIRA Server 6.4
reaches its Atlassian Support end of life date on March 17, 2017, so it's recommended to upgrade to a version of
JIRA Software (7.0 or later).");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/jira/jira-security-advisory-2017-03-09-879243455.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.2.4", test_version2: "6.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
