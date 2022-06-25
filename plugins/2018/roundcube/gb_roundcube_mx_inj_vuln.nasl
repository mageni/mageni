###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_roundcube_mx_inj_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Roundcube Webmail < 1.3.6 MX Injection Vulnerability
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

CPE = 'cpe:/a:roundcube:webmail';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140959");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-10 13:53:54 +0700 (Tue, 10 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-9846");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.3.6 MX Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/installed");

  script_tag(name:"summary", value:"In Roundcube from versions 1.2.0 to 1.3.5, with the archive plugin enabled
and configured, it's possible to exploit the unsanitized, user-controlled '_uid' parameter to perform an MX (IMAP)
injection attack by placing an IMAP command after a %0d%0a sequence.

NOTE: this is less easily exploitable in 1.3.4 and later because of a Same Origin Policy protection mechanism.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roundcube Webmail versions 1.2.0 to 1.3.5.");

  script_tag(name:"solution", value:"Update to version 1.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/6229");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/6238");
  script_xref(name:"URL", value:"https://medium.com/@ndrbasi/cve-2018-9846-roundcube-303097048b0a");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
