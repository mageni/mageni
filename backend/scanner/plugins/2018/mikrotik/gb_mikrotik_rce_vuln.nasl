##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_rce_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# MikroTik RouterOS RCE Vulnerability
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

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140895");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 12:42:03 +0700 (Wed, 28 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-7445");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a remote code execution vulnerability in the
SMB service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The buffer overflow was found in the MikroTik RouterOS SMB service when
processing NetBIOS session request messages. Remote attackers with access to the service can exploit this
vulnerability and gain code execution on the system. The overflow occurs before authentication takes place, so it
is possible for an unauthenticated remote attacker to exploit it.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.41.3.");

  script_tag(name:"solution", value:"Update to version 6.41.3 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44290/");
  script_xref(name:"URL", value:"https://www.coresecurity.com/advisories/mikrotik-routeros-smb-buffer-overflow");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.41.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.41.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
