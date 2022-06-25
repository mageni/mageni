###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kannel_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Kannel Privilege Escalation Vulnerability
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

CPE = 'cpe:/a:kannel:kannel';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140386");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-21 15:08:29 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-14609");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Kannel Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kannel_detect.nasl");
  script_mandatory_keys("kannel/installed");

  script_tag(name:"summary", value:"Kannel is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The server daemons create a PID file after dropping privileges to a
non-root account, which might allow local users to kill arbitrary processes by leveraging access to this
non-root account for PID file modification before a root script executes a 'kill `cat /pathname`' command, as
demonstrated by bearerbox.");

  script_tag(name:"affected", value:"Kannel version 1.5.0 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://redmine.kannel.org/issues/771");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version =~ "^svn") {
  if (version_is_less_equal(version: version, test_version: "svn-r5179")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else {
  if (version_is_less_equal(version: version, test_version: "1.5.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
