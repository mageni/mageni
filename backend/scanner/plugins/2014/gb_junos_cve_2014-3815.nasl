###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2014-3815.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos SIP ALG Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105914");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-17 14:33:08 +0200 (Thu, 17 Jul 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3815");
  script_bugtraq_id(68551);

  script_name("Junos SIP ALG Denial of Service Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"DoS on SRX devices when SIP ALG is enabled");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On SRX Series devices, when SIP ALG is enabled, a certain crafted
SIP packet may cause the flowd process to crash. SIP ALG is enabled by default on SRX Series devices except
for SRX-HE devices. SRX-HE devices have SIP ALG disabled by default. The status of ALGs can beobtained by
executing the 'show security alg status' CLI command.");

  script_tag(name:"impact", value:"Repeated crashes of the flowd process constitutes an extended
denial of service condition for the SRX Series device.");

  script_tag(name:"affected", value:"Junos OS 12.1X46 and 12.1X47");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable SIP ALG or enable flow-based processing for IPv6 traffic.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10633");


  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("Junos/model");
if (!model || "SRX" >!< toupper(model))
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12.1X") {
  if ((revcomp(a:version, b:"12.1X46-D20") < 0) &&
      (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:" 12.1X47-D10") < 0) &&
           (revcomp(a:version, b:"12.1X47") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
}
