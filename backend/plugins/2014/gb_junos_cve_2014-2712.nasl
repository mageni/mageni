###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2014-2712.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos J-Web XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105905");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-29 16:10:41 +0700 (Tue, 29 Apr 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-2712");
  script_bugtraq_id(66767);

  script_name("Junos J-Web XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"Cross-Site Scripting Vulnerability in J-Web.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"J-Web is vulnerable to a cross-site scripting injection. Parameters
passed as arguments to index.php can result in the execution of scripting tags within the user's browser.");

  script_tag(name:"impact", value:"Remote attackers can inject arbitrary web script or HTML to index.php.");

  script_tag(name:"affected", value:"Junos OS 10.0, 10.4, 11.4, 12.1 and 12.2.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable J-Web.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66767");

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

if (revcomp(a:build2check, b:"20140219") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.0S25") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if ((revcomp(a:version, b:"10.4R10") < 0) &&
    (revcomp(a:version, b:"10.4") >= 0)) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R11") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R9") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X44-D30") < 0) &&
           (revcomp(a:version, b:"12.1X44") >= 0)) {
    security_message(port:0, data:desc);
  }
  else if ((revcomp(a:version, b:"12.1X45-D20") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:desc);
  }
  else if ((revcomp(a:version, b:"12.1X46-D10") < 0) &&
           (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:desc);
  }
  else if ((revcomp(a:version, b:"12.2R1") < 0) &&
           (revcomp(a:version, b:"12.2") >= 0)) {
    security_message(port:0, data:desc);
  }
}

exit(99);
