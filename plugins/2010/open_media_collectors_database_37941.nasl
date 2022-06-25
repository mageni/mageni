###############################################################################
# OpenVAS Vulnerability Test
# $Id: open_media_collectors_database_37941.nasl 14121 2019-03-13 06:21:23Z ckuersteiner $
#
# Open Media Collectors Database Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:opendb:opendb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100469");
  script_version("$Revision: 14121 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 07:21:23 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_bugtraq_id(37941);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Open Media Collectors Database Multiple Local File Include Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("open_media_collectors_database_detect.nasl");
  script_mandatory_keys("opendb/detected");

  script_tag(name:"summary", value:"Open Media Collectors Database (OpenDb) is prone to multiple local file-
include vulnerabilities because it fails to properly sanitize user-supplied input.

An attacker can exploit these vulnerabilities to obtain potentially sensitive information and execute arbitrary
local scripts in the context of the webserver process. This may allow the attacker to compromise the application
and the computer, other attacks are also possible.

OpenDb 1.5.0.4 is vulnerable, other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37941");
  script_xref(name:"URL", value:"http://sourceforge.net/project/showfiles.php?group_id=37089&package_id=29402&release_id=573315");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
