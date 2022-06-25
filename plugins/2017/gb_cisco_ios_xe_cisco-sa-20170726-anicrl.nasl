###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20170726-anicrl.nasl 12109 2018-10-26 06:57:05Z cfischer $
#
# Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106990");
  script_cve_id("CVE-2017-6664");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12109 $");

  script_name("Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anicrl");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Administrators can mitigate this vulnerability by doing the following for autonomic nodes that were disconnected from the Autonomic Network domain:

  - Ensure that the certificate and key information for the node is deleted properly

  - Update the Autonomic Networking whitelist file on the registrar

  These actions will prevent the autonomic node from re-establishing connectivity to the Autonomic Network domain of an affected system.");

  script_tag(name:"summary", value:"A vulnerability in the Autonomic Networking feature of Cisco IOS XE Software could allow an unauthenticated, remote, autonomic node to access the Autonomic Networking infrastructure of an affected system, after the certificate for the autonomic node has been revoked.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software does not transfer certificate revocation lists (CRLs) across Autonomic Control Plane (ACP) channels. An attacker could exploit this vulnerability by connecting an autonomic node, which has a known and revoked certificate, to the autonomic domain of an affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to insert a previously trusted autonomic node into the autonomic domain of an affected system after the certificate for the node has been revoked.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:57:05 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-28 08:55:11 +0700 (Fri, 28 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
		'16.5.1c',
		'16.6.1',
		'3.10.8S',
		'3.10.8aS',
		'3.12.0S',
		'3.12.1S',
		'3.12.2S',
		'3.12.3S',
		'3.12.4S',
		'3.13.1S',
		'3.13.2S',
		'3.13.4S',
		'3.13.5S',
		'3.14.0S',
		'3.14.1S',
		'3.14.2S',
		'3.14.3S',
		'3.14.4S',
		'3.15.0S',
		'3.15.1S',
		'3.15.2S',
		'3.15.3S',
		'3.16.0S',
		'3.16.1aS',
		'3.16.2S',
		'3.16.2aS',
		'3.17.0S',
		'3.17.1S',
		'3.18.0S');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);