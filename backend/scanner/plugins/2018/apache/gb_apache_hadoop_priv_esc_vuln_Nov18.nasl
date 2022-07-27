##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_priv_esc_vuln_Nov18.nasl 12656 2018-12-05 03:13:01Z ckuersteiner $
#
# Apache Hadoop < 2.7.7 Privilege Escalation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141753");
  script_version("$Revision: 12656 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 04:13:01 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-05 09:20:40 +0700 (Wed, 05 Dec 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2018-11766");
  script_bugtraq_id(106035);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop < 2.7.7 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"In Apache Hadoop 2.7.4 to 2.7.6, the security fix for CVE-2016-6811 is
incomplete. A user who can escalate to yarn user can possibly run arbitrary commands as root user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host");

  script_tag(name:"affected", value:"Apache Hadoop 2.7.4 to 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.7 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/11/27/2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.7.4", test_version2: "2.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
