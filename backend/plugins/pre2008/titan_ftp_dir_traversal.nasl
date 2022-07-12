###############################################################################
# OpenVAS Vulnerability Test
# $Id: titan_ftp_dir_traversal.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# Titan FTP Server directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:southrivertech:titan_ftp_server";

# Ref: D4rkGr3y

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14659");
  script_version("2019-04-09T13:55:37+0000");
  script_tag(name:"last_modification", value:"2019-04-09 13:55:37 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7718);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Titan FTP Server directory traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("gb_titan_ftp_detect.nasl");
  script_mandatory_keys("TitanFTP/detected");

  script_tag(name:"summary", value:"The remote host is running Titan FTP Server. All versions up to and
  including 2.02 are reported vulnerable to a directory traversal flaw.");

  script_tag(name:"impact", value:"An attacker could send specially crafted URL to view arbitrary files on the
  system.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.02")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Unknown");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);