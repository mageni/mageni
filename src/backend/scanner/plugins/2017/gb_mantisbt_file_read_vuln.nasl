###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_file_read_vuln.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Arbitrary File Read Vulnerability
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

CPE = 'cpe:/a:mantisbt:mantisbt';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140285");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-08-08 15:08:03 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2017-12419");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("MantisBT Arbitrary File Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"summary", value:"MantisBT is prone to an arbitrary file read vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"If, after successful installation of MantisBT on MySQL/MariaDB, the
administrator does not remove the 'admin' directory (as recommended in the 'Post-installation and upgrade tasks'
section of the MantisBT Admin Guide), and the MySQL client has a local_infile setting enabled (in php.ini
mysqli.allow_local_infile, or the MySQL client config file, depending on the PHP setup), an attacker may take
advantage of MySQL's 'connect file read' feature to remotely access files on the MantisBT server.");

  script_tag(name:"affected", value:"MantisBT version 1.x and 2.x.");

  script_tag(name:"solution", value:"Delete the 'admin' directory, disabling mysqli.allow_local_infile in php.ini.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=23173");
  script_xref(name:"URL", value:"https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.install.postcommon");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/admin/install.php?install=3";

if (http_vuln_check(port: port, url: url, pattern: "Installing Database", check_header: TRUE)) {
  report = "The installer script is accessible at " + report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
