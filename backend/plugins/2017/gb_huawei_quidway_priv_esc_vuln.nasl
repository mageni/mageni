###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_quidway_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Huawei Quidway Switches Privilege Escalation Vulnerability
#
# Authors:
# INCIBE <ics-team@incibe.es>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106571");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2015-1460");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Quidway Switches Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_huawei_switch_detect.nasl");
  script_mandatory_keys("huawei_switch/detected", "huawei_switch/model", "huawei_switch/version");

  script_tag(name:"summary", value:"Huawei Quidway switches are prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Huawei Quidway switches allows remote attackers to gain privileges via a
crafted packet.");

  script_tag(name:"impact", value:"Attackers may exploit this vulnerability to obtain higher access
permissions.");

  script_tag(name:"affected", value:"Quidway S2350, S2750, S5300, S5700, S6300, S6700, S7700, S9300, S9300E and
S9700 with versions prior to V200R005C00SPC300");

  script_tag(name:"solution", value:"Upgrade to Version V200R005C00SPC300 or later");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/hw-411975");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

model = get_kb_item("huawei_switch/model");
if (model !~ "^S(2350|2750|530|570|630|670|770|930|930.E|97)")
  exit(0);

if (!version = get_kb_item("huawei_switch/version"))
  exit(0);

if (revcomp(a: version, b: "v200r005c00spc300") < 0) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "V200R005C00SPC300");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
