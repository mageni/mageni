###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2013-6618.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos J-Web Sajax Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = 'cpe:/o:juniper:junos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105911");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-16 11:33:56 +0700 (Mon, 16 Jun 2014)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-6618");
  script_bugtraq_id(62305);

  script_name("Junos J-Web Sajax Remote Code Execution Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"Remote Code Execution on J-Web");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Juniper Junos could allow a remote authenticated attacker to execute
arbitrary commands on the system, caused by the failure to restrict access to /jsdm/ajax/port.php. If J-Web
is enabled, an attacker could send specially-crafted data to execute arbitrary OS commands on the system
with root privileges.");

  script_tag(name:"impact", value:"A user with low privilege (such as read only access) may get complete
administrative access. The vulnerability is limited to only users with valid, authenticated login credentials.");

  script_tag(name:"affected", value:"Junos OS 10.4, 11.4, 12.1, 12.2 and 12.3.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable J-Web.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10560");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62305");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20130228") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R13") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R5") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X44-D15") < 0) &&
           (revcomp(a:version, b:"12.1X44") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X45-D10") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.2R3") < 0) &&
           (revcomp(a:version, b:"12.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.3R1") < 0) &&
           (revcomp(a:version, b:"12.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
