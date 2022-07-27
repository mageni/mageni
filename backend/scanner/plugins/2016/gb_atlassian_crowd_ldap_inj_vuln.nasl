###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_crowd_ldap_inj_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Atlassian Crowd LDAP Java Object Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:atlassian:crowd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106375");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-6496");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Crowd LDAP Java Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_atlassian_crowd_detect.nasl");
  script_mandatory_keys("atlassian_crowd/installed");

  script_tag(name:"summary", value:"Atlassian Crowd is prone to a LDAP Java object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Crowd LDAP directory connector allowed an attacker to gain remote code
execution in Crowd by injecting malicious attributes in LDAP entries. To exploit this issue, attackers need to
modify an entry in your LDAP directory or successfully execute a Man-in-The-Middle attack between an LDAP server
and Crowd. Crowd installations configured to communicate with an LDAP server using the LDAPS protocol with the
Secure SSL option enabled are immune to this attack vector only (unless an attacker is able to obtain the private
key of the SSL/TLS certificate used to secure the communication).");

  script_tag(name:"impact", value:"An attacker may execute remote code.");

  script_tag(name:"affected", value:"Crowd from 1.4.1 before 2.8.8 and from 2.9.0 before 2.9.5");

  script_tag(name:"solution", value:"Update to 2.8.8, 2.9.5 or later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CWD-4790?src=confmacro");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_in_range(version: version, test_version: "1.4.1", test_version2: "2.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.9.0", test_version2: "2.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
