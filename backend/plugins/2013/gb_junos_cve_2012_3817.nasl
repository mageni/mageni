###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2012_3817.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos DNSSEC validation Denial of Service
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103948");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-15 21:39:27 +0700 (Tue, 15 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2012-3817");
  script_bugtraq_id(54658);

  script_name("Junos DNSSEC validation Denial of Service");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"Heavy DNSSEC validation load can cause assertion failure in Bind
of Junos OS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"BIND stores a cache of query names that are known to be failing
due to misconfigured name servers or a broken chain of trust. Under high query loads, when DNSSEC
validation is active, it is possible for a condition to arise in which data from this cache of failing
queries could be used before it was fully initialized, triggering an assertion failure.");

  script_tag(name:"impact", value:"An attacker that is able to generate high volume of DNSSEC
validation enabled queries can trigger the assertion failure that causes it to crash, resulting in a
denial of service.");

  script_tag(name:"affected", value:"Junos OS software build before 2013-02-13.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As
a workaround disable the security extension if DNSSEC is not required by typing delete system services
dns dnssec.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10556");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54658");

  exit(0);
}

include("version_func.inc");

version = get_kb_item("Junos/Version");
if (!version)
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (version_is_greater(version:build2check, test_version:"20130212")) {
  exit(99);
}

if (version_is_less(version:version, test_version:"10.4R13")) {
  security_message(port:0, data:desc);
  exit(0);
}

if (ereg(pattern:"^11", string:version)) {
  if (version_is_less(version:version, test_version:"11.4.R6")) {
    security_message(port:0, data:desc);
    exit(0);
  } else if (version_is_less(version:version, test_version:"11.4X27.43") &&
             version_is_greater(version:version, test_version:"11.4.X")) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (ereg(pattern:"^12.1", string:version)) {
  if (version_is_less(version:version, test_version:"12.1R5")) {
    security_message(port:0, data:desc);
    exit(0);
  } else if (version_is_less(version:version, test_version:"12.1X44-D15") &&
             version_is_greater(version:version, test_version:"12.1X"))  {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (ereg(pattern:"^12.2", string:version)) {
  if (version_is_less(version:version, test_version:"12.2R3")) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (ereg(pattern:"^12.3", string:version)) {
  if (version_is_less(version:version, test_version:"12.3R1")) {
    security_message(port:0, data:desc);
    exit(0);
  } else if (version_is_less(version:version, test_version:"12.3X50-D11") &&
             version_is_greater(version:version, test_version:"12.3X")) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

exit(99);
