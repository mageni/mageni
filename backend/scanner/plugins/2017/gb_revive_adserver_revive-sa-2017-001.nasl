###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_revive_adserver_revive-sa-2017-001.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Revive Adserver Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:revive:adserver';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106559");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 13:44:37 +0700 (Thu, 02 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5830", "CVE-2017-5831", "CVE-2017-5832", "CVE-2017-5833");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Revive Adserver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_revive_adserver_detect.nasl");
  script_mandatory_keys("ReviveAdserver/Installed");

  script_tag(name:"summary", value:"Revive Adserver is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Revive Adserver is prone to multiple vulnerabilities:

  - Revive Adserver does unserializing untrusted data submitted via cookies in the delivery scripts. An attacker
could use such vector to either perform generic RCE attacks (e.g. when a vulnerable PHP version is being used) or,
potentially, application-specific attacks.

  - Revive Adserver isn't properly invalidating the current session when setting a new password via the forgot
password mechanism. This could allow attackers having access to the session ID to keep the authenticated session
alive.

  - Revive Adserver is vulnerable to a persistent XSS attack: an authenticated user could set their own email
address to a specifically crafted string which is then displayed without proper escaping in the context of other
users (e.g. the administrator user), giving them an opportunity to steal a session with elevated privileges.

  - Revive Adserver is vulnerable to a reflected XSS attack: several of the parameters used in the invocation code
generation for interstitial zones aren't properly escaped when displayed.");

  script_tag(name:"impact", value:"A remote attacker may gain complete control.");

  script_tag(name:"affected", value:"Revive Adserver version 4.0.0 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.1 or later");

  script_xref(name:"URL", value:"https://www.revive-adserver.com/security/revive-sa-2017-001/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
