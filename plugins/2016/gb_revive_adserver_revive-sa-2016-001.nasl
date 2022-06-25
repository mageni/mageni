###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_revive_adserver_revive-sa-2016-001.nasl 14130 2019-03-13 07:53:41Z mmartin $
#
# Revive Adserver Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106321");
  script_version("$Revision: 14130 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 08:53:41 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-04 11:58:57 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2016-9124", "CVE-2016-9125", "CVE-2016-9126", "CVE-2016-9127", "CVE-2016-9128",
                "CVE-2016-9129", "CVE-2016-9130", "CVE-2016-9454", "CVE-2016-9455", "CVE-2016-9456",
                "CVE-2016-9457");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Revive Adserver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_revive_adserver_detect.nasl");
  script_mandatory_keys("ReviveAdserver/Installed");

  script_tag(name:"summary", value:"Revive Adserver is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Revive Adserver is prone to multiple vulnerabilities:

  - The login page of Revive Adserver is vulnerable to password-guessing attacks. An account lockdown feature was
considered, but rejected to avoid introducing service disruptions to regular users during such attacks. A random
delay has instead been introduced as a counter-measure in case of password failures, along with a system to
discourage parallel brute forcing. These systems will effectively allow the valid users to log in to the
adserver, even while an attack is in progress.

  - Revive Adserver is vulnerable to session fixation, by allowing arbitrary session identifiers to be forced and,
at the same time, by not invalidating the existing session upon a successful authentication. An attacker may steal
an authenticated sessions.

  - Usernames are not properly escaped when displayed in the audit trail widget of the dashboard upon login,
allowing persistent XSS attacks. An authenticated user with enough privileges to create other users could
exploit the vulnerability to access the administrator account.

  - The password recovery form in Revive Adserver is vulnerable to CSRF attacks. This vulnerability could be
exploited to send a large number of password recovery emails to the registered users, especially in conjunction
with a bug that caused recovery emails to be sent to all the users at once.

  - The affiliate-preview.php script in www/admin is vulnerable to a reflected XSS attack. This vulnerability
could be used by an attacker to steal the session ID of an authenticated user, by tricking them into visiting a
specifically crafted URL.

  - It is possible to check whether or not an email address is associated to one or more user accounts on a target
Revive Adserver instance by examining the message printed by the password recovery system.

  - Two vectors for persistent XSS attacks via the Revive Adserver user interface, both requiring a trusted
(non-admin) account: the website name isn't properly escaped when displayed in the campaign-zone.php script and
the banner image URL for external banners isn't properly escaped when displayed in most of the banner related
pages.

  - A number of scripts in Revive Adserver's user interface are vulnerable to CSRF attacks.

  - Multiple CSRF vulnerabilities were found.

  - www/admin/stats.php is vulnerable to reflected XSS attacks via multiple parameters that are not properly
sanitised or escaped when displayed, such as 'setPerPage', 'pageId', 'bannerid', 'pereiod_start', 'period_end'
and possibly others.");

  script_tag(name:"affected", value:"Revive Adserver version 3.2.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 3.2.3 or later");

  script_xref(name:"URL", value:"https://www.revive-adserver.com/security/revive-sa-2016-001/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
