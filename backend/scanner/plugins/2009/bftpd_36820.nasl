###############################################################################
# OpenVAS Vulnerability Test
# $Id: bftpd_36820.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Bftpd Unspecified Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:bftpd:bftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100320");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-28 11:13:14 +0100 (Wed, 28 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-4593");
  script_bugtraq_id(36820);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Bftpd Unspecified Remote Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_bftpd_detect.nasl");
  script_mandatory_keys("bftpd/installed");

  script_tag(name:"summary", value:"Bftpd is prone to an unspecified remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Successful exploits will cause the affected application to crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Bftpd 2.4 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 2.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36820");
  script_xref(name:"URL", value:"http://bftpd.sourceforge.net/index.html");
  script_xref(name:"URL", value:"http://bftpd.sourceforge.net/news.html#032130");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);