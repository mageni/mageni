###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10790.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos SRX Series: MACsec Failure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106944");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 12:08:53 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2017-2342");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos SRX Series: MACsec Failure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Junos OS on SRX300 series are prone to a MACsec failure to report errors.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"MACsec feature does not report errors when a secure link can not be
established. It falls back to an unencrypted link. This can happen when MACsec is configured on ports that are
not capable of MACsec or when a secure link can not be established. This can mislead customers into believing
that a link is secure.");

  script_tag(name:"affected", value:"Junos OS 15.1X49 on SRX300 Series.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10790");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model = get_kb_item("Junos/model");
if (!model || (toupper(model) !~ '^SRX3..'))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "15.1X49-D100") < 0) &&
    (revcomp(a: version, b: "15.1X49") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D100");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
