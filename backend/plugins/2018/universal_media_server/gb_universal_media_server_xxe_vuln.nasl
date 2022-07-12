###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_universal_media_server_xxe_vuln.nasl 13858 2019-02-26 04:17:07Z ckuersteiner $
#
# Universal Media Server XXE Vulnerability
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

CPE = "cpe:/a:universal_media_server:universal_media_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141352");
  script_version("$Revision: 13858 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 05:17:07 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-08-07 08:45:28 +0700 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-13416");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Universal Media Server XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_universal_media_server_detect.nasl");
  script_mandatory_keys("universal_media_server/installed");

  script_tag(name:"summary", value:"In Universal Media Server (UMS), the XML parsing engine for SSDP/UPnP
functionality is vulnerable to an XML External Entity Processing (XXE) attack. Remote, unauthenticated attackers
can use this vulnerability to: Access arbitrary files from the filesystem with the same permission as the user
account running UMS, Initiate SMB connections to capture a NetNTLM challenge/response and crack to cleartext
password, or Initiate SMB connections to relay a NetNTLM challenge/response and achieve Remote Command Execution
in Windows domains.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Universal Media Server version 7.1.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 26th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45133/");
  script_xref(name:"URL", value:"https://github.com/UniversalMediaServer/UniversalMediaServer/issues/1522");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
