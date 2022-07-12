###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_sinema_priv_esc_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Siemens SINEMA Server Privilege Escalation Vulnerability
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

CPE = 'cpe:/a:siemens:sinema_server';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106221");
  script_version("$Revision: 12338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-02 14:50:41 +0700 (Fri, 02 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-6486");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Siemens SINEMA Server Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_siemens_sinema_server_detect.nasl");
  script_mandatory_keys("sinema_server/installed", "sinema_server/version");

  script_tag(name:"summary", value:"SINEMA Server is affected by a vulnerability that could allow
authenticated operating system users to escalate their privileges.");

  script_tag(name:"insight", value:"The file permissions set for the SINEMA Server application folder could
allow users, authenticated via the operating system, to escalate their privileges.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow users,
authenticated via the operating system, to escalate their privileges under certain conditions.");

  script_tag(name:"affected", value:"SINEMA Server V13 and prior.");

  script_tag(name:"solution", value:"Siemens provides a temporary fix for existing installations through
its local service organization.");

  script_xref(name:"URL", value:"http://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-321174.pdf");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-215-02");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
