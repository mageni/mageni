###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10791.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos SRX Series: Hardcoded Credentials Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/o:juniper:junos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106943");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 11:36:34 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-2343");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos SRX Series: Hardcoded Credentials Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Junos OS on SRX series contain hardcoded credentials.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"As part of an internal security review of the UserFW services authentication
API, hardcoded credentials were identified and removed which can impact both the SRX Series device, and
potentially LDAP and Active Directory integrated points.

Credentials may be taken from the network via man-in-the-middle attacks, or other attack vectors, as above, or
others not listed.");

  script_tag(name:"impact", value:"An attacker may be able to completely compromise both the SRX Series device
without authentication, other SRX Series devices deployed in the same environment running vulnerable versions of
Junos OS, as well as Active Directory servers and service, including but not limited to, user accounts,
workstations, servers performing other functions such as email, database, etc. which are also tied to the Active
Directory deployment. Inter-Forest Active Directory deployments may also be at risk as the attacker may gain full
administrative control over one or more Active Directories depending on the credentials supplied by the
administrator of the AD domains and SRX devices performing integrated authentication of users, groups and
devices.");

  script_tag(name:"affected", value:"Junos OS 12.3X48 and 15.1X49 on SRX Series.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10791");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model = get_kb_item("Junos/model");
if (!model || (toupper(model) !~ '^SRX'))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "12.3X48-D35") < 0) &&
    (revcomp(a: version, b: "12.3X48-D30") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D35");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "15.1X49-D50") < 0) &&
    (revcomp(a: version, b: "15.1X49-D40") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D50");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
